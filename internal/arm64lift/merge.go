package arm64lift

import "math/bits"

// cfgAnalysis holds the per-function control-flow facts this lifter's
// merge-point reconstruction needs: how many known predecessors each
// block has (a genuine merge point has at least two), and each block's
// immediate post-dominator (the closest block every path leaving it
// must eventually reach, or 0 when there is none / it would be the
// synthetic function-exit node).
//
// This exists so a conditional split whose two arms reconverge can lift
// the shared continuation ONCE after the if/else, with each arm jumping
// to it via a LabelStmt/GotoStmt pair, instead of every fork lifting the
// entire downstream graph for itself. The old per-fork model produced
// output exponential in the number of sequential conditions - a real
// parse_args-style function could balloon to tens of megabytes of
// duplicated nested branches.
type cfgAnalysis struct {
	preds map[uint64]int
	ipdom map[uint64]uint64
	// partialIPDom is a second, deliberately looser set of merge points:
	// the immediate post-dominator computed while treating terminating
	// paths (returns, unresolved tail calls) as imposing NO constraint -
	// see analyzePartialPostdom. It is only consulted where ipdom has no
	// answer, and its whole purpose is the very common shape ipdom
	// cannot handle: if/else chains in which one arm returns early, so
	// the only block standard post-dominance finds is the function exit
	// and the chain's real shared continuation (e.g. a loop's tail)
	// would otherwise never be recognized as a merge at all.
	partialIPDom map[uint64]uint64
}

// partialPostdomBlocks caps how large a function gets the bitset
// partial-post-dominator treatment. Beyond it, the fallback is simply
// skipped (standard ipdom still applies), which is always safe.
const partialPostdomBlocks = 1024

// exitNode is the synthetic sink every control path leaving the known
// function graph (a leaf block, or a branch whose target isn't a block
// in byAddr - e.g. a tail call) is treated as reaching. It only exists
// inside analyzeCFG's own dominator computation and is never returned
// as a merge point.
const exitNode = ^uint64(0)

// analyzeCFG computes preds and immediate post-dominators for one
// function's basic-block graph using the standard Cooper-Harvey-Kennedy
// iterative dominated-node algorithm, run on the REVERSE CFG (edges
// flipped) rooted at a synthetic exit node. Blocks that cannot reach
// that exit at all (a path that loops forever) simply have no
// post-dominator, so they never become merge points - the safe outcome.
func analyzeCFG(blocks []*BasicBlock) *cfgAnalysis {
	a := &cfgAnalysis{
		preds: computePredCounts(blocks),
		ipdom: make(map[uint64]uint64),
	}
	if len(blocks) == 0 {
		return a
	}

	byAddr := make(map[uint64]*BasicBlock, len(blocks))
	for _, b := range blocks {
		byAddr[b.StartAddr] = b
	}

	// succs[b] are b's forward successors, with any edge that leaves the
	// known graph redirected to exitNode; revSuccs is that same edge set
	// with the direction flipped, which is the CFG the post-dominator
	// computation walks.
	succs := make(map[uint64][]uint64, len(blocks)+1)
	revSuccs := make(map[uint64][]uint64, len(blocks)+1)
	addEdge := func(from, to uint64) {
		succs[from] = append(succs[from], to)
		revSuccs[to] = append(revSuccs[to], from)
	}
	for _, b := range blocks {
		if len(b.Succs) == 0 {
			addEdge(b.StartAddr, exitNode)
			continue
		}
		for _, s := range b.Succs {
			if _, ok := byAddr[s]; !ok {
				s = exitNode
			}
			addEdge(b.StartAddr, s)
		}
	}

	// Reverse postorder of the reverse CFG rooted at exitNode: only
	// blocks the exit can reach (in the reverse graph, i.e. blocks that
	// can reach the exit going forward) get an idom at all.
	var post []uint64
	seen := map[uint64]bool{}
	var dfs func(n uint64)
	dfs = func(n uint64) {
		seen[n] = true
		for _, s := range revSuccs[n] {
			if !seen[s] {
				dfs(s)
			}
		}
		post = append(post, n)
	}
	dfs(exitNode)
	order := make([]uint64, len(post))
	for i, n := range post {
		order[len(post)-1-i] = n
	}

	rpoNum := make(map[uint64]int, len(order))
	for i, n := range order {
		rpoNum[n] = i
	}

	a.ipdom[exitNode] = exitNode
	intersect := func(x, y uint64) uint64 {
		// Advance whichever finger is DEEPER in reverse postorder
		// (larger index - the exit root is index 0): an idom is always
		// closer to the root than the node it dominates, so this walk
		// monotonically climbs both fingers to their common dominator.
		for x != y {
			for rpoNum[x] > rpoNum[y] {
				x = a.ipdom[x]
			}
			for rpoNum[y] > rpoNum[x] {
				y = a.ipdom[y]
			}
		}
		return x
	}

	for changed := true; changed; {
		changed = false
		for _, b := range order[1:] {
			newIdom := uint64(0)
			for _, p := range succs[b] {
				if a.ipdom[p] == 0 {
					continue
				}
				if newIdom == 0 {
					newIdom = p
				} else {
					newIdom = intersect(p, newIdom)
				}
			}
			if newIdom != 0 && a.ipdom[b] != newIdom {
				a.ipdom[b] = newIdom
				changed = true
			}
		}
	}

	// The synthetic exit (and a block that is its own post-dominator)
	// means "no real shared merge block".
	for b, p := range a.ipdom {
		if b == exitNode {
			continue
		}
		if p == exitNode || p == b {
			delete(a.ipdom, b)
		}
	}

	a.partialIPDom = analyzePartialPostdom(blocks, byAddr, a.preds, len(blocks))
	return a
}

// isTerminalBlock reports whether b ends the function on its own: an
// explicit ret, or a branch whose target left the known block graph
// (an indirect "br" tail call, or a "b <external symbol>" tail call).
// No Succs at all is the common case.
func isTerminalBlock(b *BasicBlock, byAddr map[uint64]*BasicBlock) bool {
	if len(b.Succs) == 0 {
		return true
	}
	for _, s := range b.Succs {
		if _, ok := byAddr[s]; ok {
			return false
		}
	}
	return true
}

// analyzePartialPostdom computes "merge points ignoring terminating
// paths": the closest block every NON-terminating path from each block
// still reaches. Standard post-dominance (analyzeCFG) breaks down for
// real command-dispatch chains, because the moment one arm of a split
// returns early, the only block all paths share is the function exit -
// so the chain's actual shared continuation is never found and every
// fork duplicates the entire rest of the function (exponential output).
//
// Sets are computed as a least-fixpoint bitset dataflow over the
// participating blocks (every non-terminal block, plus each terminal
// block that is a genuine join - see the node selection below), each
// set seeded with its own block:
//
//	postdom[b] = {b} ∪ ( ∩ postdom[s] for every participating successor s )
//
// where a block with no participating successor keeps just {b} (nothing
// is constrained beyond the block itself). Seeding must start from the
// bottom, not the universe: the transfer is inflationary (it always
// adds b), so a top-seeded greatest-fixpoint iteration would leave
// every set full and answer nothing at all. The immediate post-dominator
// is then the unique candidate m != b whose own set contains every other
// candidate - i.e. the closest node all paths still share. Sets that
// grow to the full universe mean no constraint survived, and ties
// (several equally close candidates) are skipped: both are the safe,
// conservative outcome.
//
// Because a cycle whose only exits are terminal blocks keeps every
// block in its strongly connected component "sharing" all the others,
// such functions produce no usable partial merges and simply keep the
// standard behavior - the fallback is never worse than not having it.
func analyzePartialPostdom(blocks []*BasicBlock, byAddr map[uint64]*BasicBlock, preds map[uint64]int, n0 int) map[uint64]uint64 {
	out := make(map[uint64]uint64)
	if n0 == 0 || n0 > partialPostdomBlocks {
		return out
	}

	// Non-terminal blocks always participate. A TERMINAL block
	// participates only when it is a genuine join (two or more
	// predecessors): a shared return/epilogue reached from multiple
	// paths is a perfectly good merge candidate - in fact the common
	// shape once simplifyCFG folds the function's final "ret" into the
	// continuation - whereas a single-predecessor terminal is just the
	// end of one path (an early return) and must not constrain the
	// analysis at all, which is what lets an early-returning arm be
	// ignored while the other arm's continuation is still found.
	nodes := make([]uint64, 0, len(blocks))
	idx := make(map[uint64]int, len(blocks))
	for _, b := range blocks {
		if isTerminalBlock(b, byAddr) && preds[b.StartAddr] < 2 {
			continue
		}
		idx[b.StartAddr] = len(nodes)
		nodes = append(nodes, b.StartAddr)
	}
	n := len(nodes)
	if n == 0 {
		return out
	}
	words := (n + 63) / 64

	succs := make([][]int, n)
	for i, addr := range nodes {
		b := byAddr[addr]
		for _, s := range b.Succs {
			if j, ok := idx[s]; ok {
				succs[i] = append(succs[i], j)
			}
		}
	}

	postdom := make([][]uint64, n)
	for i := range postdom {
		set := make([]uint64, words)
		set[i/64] = uint64(1) << (uint(i) % 64)
		postdom[i] = set
	}

	tmp := make([]uint64, words)
	for changed := true; changed; {
		changed = false
		for i := range nodes {
			// Intersect the participating successors' sets, growing each
			// block's set from its own singleton towards the least
			// fixpoint above. A block with no participating successor
			// contributes no constraint at all, so its set stays {i}.
			if len(succs[i]) == 0 {
				for w := range tmp {
					tmp[w] = 0
				}
			} else {
				copy(tmp, postdom[succs[i][0]])
				for _, j := range succs[i][1:] {
					sj := postdom[j]
					for w := range tmp {
						tmp[w] &= sj[w]
					}
				}
			}
			tmp[i/64] |= uint64(1) << (uint(i) % 64)
			if !equalWords(tmp, postdom[i]) {
				copy(postdom[i], tmp)
				changed = true
			}
		}
	}

	for i := range nodes {
		set := postdom[i]
		if allSet(set, n) {
			continue
		}
		cand := make([]uint64, words)
		copy(cand, set)
		cand[i/64] &^= uint64(1) << (uint(i) % 64)
		if wordIsZero(cand) {
			continue
		}
		chosen := -1
		count := 0
		for w, word := range cand {
			for word != 0 {
				bit := bits.TrailingZeros64(word)
				word &= word - 1
				j := w*64 + bit
				if j >= n {
					continue
				}
				if containsAll(postdom[j], cand) {
					count++
					chosen = j
				}
			}
		}
		if count == 1 {
			out[nodes[i]] = nodes[chosen]
		}
	}
	return out
}

// containsAll reports whether every bit set in want is also set in set.
func containsAll(set, want []uint64) bool {
	for w := range want {
		if want[w]&^set[w] != 0 {
			return false
		}
	}
	return true
}

func wordIsZero(set []uint64) bool {
	for _, w := range set {
		if w != 0 {
			return false
		}
	}
	return true
}

func equalWords(a, b []uint64) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func allSet(set []uint64, n int) bool {
	for w, word := range set {
		last := w == len(set)-1
		want := ^uint64(0)
		if last {
			if rem := n % 64; rem != 0 {
				want = (uint64(1) << rem) - 1
			}
		}
		if word != want {
			return false
		}
	}
	return true
}
