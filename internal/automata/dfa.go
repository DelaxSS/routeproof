package automata

import (
	"errors"
	"math/bits"
)

const (
	// Printable non-whitespace ASCII URL path alphabet (0x21..0x7E).
	MinByte      byte = 0x21
	MaxByte      byte = 0x7E
	AlphabetSize      = int(MaxByte - MinByte + 1)

	// DefaultMaxStates bounds DFA construction to prevent state explosion.
	DefaultMaxStates = 50000
)

// ErrStateLimit is returned when DFA construction exceeds maxStates.
var ErrStateLimit = errors.New("automata: DFA state limit exceeded")

// byteSet represents a subset of [MinByte..MaxByte] using bits 0..93.
type byteSet [2]uint64

func allByteSet() byteSet {
	return byteSet{
		^uint64(0),
		(uint64(1) << (AlphabetSize - 64)) - 1,
	}
}

func (b *byteSet) set(ch byte) {
	if ch < MinByte || ch > MaxByte {
		return
	}
	idx := int(ch - MinByte)
	b[idx/64] |= 1 << (idx % 64)
}

func (b byteSet) has(ch byte) bool {
	if ch < MinByte || ch > MaxByte {
		return false
	}
	idx := int(ch - MinByte)
	return (b[idx/64] & (1 << (idx % 64))) != 0
}

func (b byteSet) isEmpty() bool {
	return b[0] == 0 && b[1] == 0
}

func (b byteSet) and(other byteSet) byteSet {
	return byteSet{b[0] & other[0], b[1] & other[1]}
}

func (b byteSet) andNot(other byteSet) byteSet {
	return byteSet{b[0] &^ other[0], b[1] &^ other[1]}
}

func (b byteSet) firstByte() byte {
	if b[0] != 0 {
		return MinByte + byte(bits.TrailingZeros64(b[0]))
	}
	return MinByte + 64 + byte(bits.TrailingZeros64(b[1]))
}

// DFA is a totalized deterministic finite automaton over ASCII bytes [MinByte..MaxByte]
// compressed with byte equivalence classes.
type DFA struct {
	numStates   int
	numClasses  int
	start       int
	classOf     [AlphabetSize]uint8
	transitions []int // flattened [state*numClasses + class]
	accept      []bool
}

// Empty returns a DFA that accepts no strings.
func Empty() *DFA {
	return &DFA{
		numStates:   1,
		numClasses:  1,
		start:       0,
		transitions: []int{0},
		accept:      []bool{false},
	}
}

// Universal returns a DFA that accepts every string over [MinByte..MaxByte].
func Universal() *DFA {
	return &DFA{
		numStates:   1,
		numClasses:  1,
		start:       0,
		transitions: []int{0},
		accept:      []bool{true},
	}
}

// NumStates returns the number of states in the DFA.
func (d *DFA) NumStates() int {
	return d.numStates
}

// NumClasses returns the number of byte equivalence classes in the DFA.
func (d *DFA) NumClasses() int {
	return d.numClasses
}

// Accepts reports whether s is accepted by the DFA.
// Strings containing bytes outside [MinByte..MaxByte] are rejected.
func (d *DFA) Accepts(s string) bool {
	state := d.start
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < MinByte || ch > MaxByte {
			return false
		}
		cls := int(d.classOf[ch-MinByte])
		state = d.transitions[state*d.numClasses+cls]
	}
	return d.accept[state]
}

// IsEmpty reports whether the DFA accepts no strings.
func (d *DFA) IsEmpty() bool {
	visited := make([]bool, d.numStates)
	queue := make([]int, 0, d.numStates)
	visited[d.start] = true
	queue = append(queue, d.start)

	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		if d.accept[u] {
			return false
		}
		base := u * d.numClasses
		for c := 0; c < d.numClasses; c++ {
			v := d.transitions[base+c]
			if !visited[v] {
				visited[v] = true
				queue = append(queue, v)
			}
		}
	}
	return true
}

// Complement returns a DFA accepting the complement language over [MinByte..MaxByte]*.
func (d *DFA) Complement() *DFA {
	trans := make([]int, len(d.transitions))
	copy(trans, d.transitions)

	acc := make([]bool, len(d.accept))
	for i, a := range d.accept {
		acc[i] = !a
	}

	return &DFA{
		numStates:   d.numStates,
		numClasses:  d.numClasses,
		start:       d.start,
		classOf:     d.classOf,
		transitions: trans,
		accept:      acc,
	}
}

// Intersect returns a DFA accepting L(d) ∩ L(other).
// If maxStates <= 0, DefaultMaxStates is used.
func (d *DFA) Intersect(other *DFA, maxStates int) (*DFA, error) {
	return product(d, other, maxStates, func(a, b bool) bool { return a && b })
}

// Union returns a DFA accepting L(d) ∪ L(other).
// If maxStates <= 0, DefaultMaxStates is used.
func (d *DFA) Union(other *DFA, maxStates int) (*DFA, error) {
	return product(d, other, maxStates, func(a, b bool) bool { return a || b })
}

// Difference returns a DFA accepting L(d) \ L(other).
// If maxStates <= 0, DefaultMaxStates is used.
func (d *DFA) Difference(other *DFA, maxStates int) (*DFA, error) {
	return product(d, other, maxStates, func(a, b bool) bool { return a && !b })
}

// Concat returns a DFA accepting L(d) · L(other).
// If maxStates <= 0, DefaultMaxStates is used.
func (d *DFA) Concat(other *DFA, maxStates int) (*DFA, error) {
	maxStates = normalizeMaxStates(maxStates)
	if d.IsEmpty() || other.IsEmpty() {
		return Empty(), nil
	}
	return concatDFAs(d, other, maxStates)
}

func normalizeMaxStates(maxStates int) int {
	if maxStates <= 0 {
		return DefaultMaxStates
	}
	return maxStates
}

func product(a, b *DFA, maxStates int, combine func(bool, bool) bool) (*DFA, error) {
	maxStates = normalizeMaxStates(maxStates)
	classOf, mapA, mapB, numClasses := refineClasses(a.classOf, b.classOf)

	type pair struct {
		sA, sB int
	}

	seen := make(map[uint64]int)
	queue := make([]pair, 0, 64)
	var transitions []int
	var accept []bool

	addState := func(sA, sB int) (int, error) {
		key := (uint64(sA) << 32) | uint64(sB)
		if id, ok := seen[key]; ok {
			return id, nil
		}
		if len(accept) >= maxStates {
			return -1, ErrStateLimit
		}
		id := len(accept)
		seen[key] = id
		queue = append(queue, pair{sA, sB})
		accept = append(accept, combine(a.accept[sA], b.accept[sB]))
		transitions = append(transitions, make([]int, numClasses)...)
		return id, nil
	}

	if _, err := addState(a.start, b.start); err != nil {
		return nil, err
	}

	for id := 0; id < len(queue); id++ {
		p := queue[id]
		baseA := p.sA * a.numClasses
		baseB := p.sB * b.numClasses
		baseOut := id * numClasses
		for c := 0; c < numClasses; c++ {
			nextA := a.transitions[baseA+int(mapA[c])]
			nextB := b.transitions[baseB+int(mapB[c])]
			nextID, err := addState(nextA, nextB)
			if err != nil {
				return nil, err
			}
			transitions[baseOut+c] = nextID
		}
	}

	res := &DFA{
		numStates:   len(accept),
		numClasses:  numClasses,
		start:       0,
		classOf:     classOf,
		transitions: transitions,
		accept:      accept,
	}
	return res.Minimize(), nil
}

// refineClasses computes the coarsest common refinement of two byte partitions.
func refineClasses(a, b [AlphabetSize]uint8) (classOf [AlphabetSize]uint8, mapA, mapB []uint8, numClasses int) {
	pairToClass := make(map[uint16]uint8, 32)
	for i := 0; i < AlphabetSize; i++ {
		key := (uint16(a[i]) << 8) | uint16(b[i])
		cls, ok := pairToClass[key]
		if !ok {
			cls = uint8(numClasses)
			pairToClass[key] = cls
			mapA = append(mapA, a[i])
			mapB = append(mapB, b[i])
			numClasses++
		}
		classOf[i] = cls
	}
	return classOf, mapA, mapB, numClasses
}

// Minimize returns an equivalent minimal totalized DFA using Hopcroft's algorithm.
func (d *DFA) Minimize() *DFA {
	// Keep only states reachable from start.
	remap := make([]int, d.numStates)
	for i := range remap {
		remap[i] = -1
	}
	order := make([]int, 0, d.numStates)
	remap[d.start] = 0
	order = append(order, d.start)

	for i := 0; i < len(order); i++ {
		u := order[i]
		base := u * d.numClasses
		for c := 0; c < d.numClasses; c++ {
			v := d.transitions[base+c]
			if remap[v] == -1 {
				remap[v] = len(order)
				order = append(order, v)
			}
		}
	}

	n := len(order)
	k := d.numClasses
	trans := make([]int, n*k)
	acc := make([]bool, n)
	var accStates, nonAccStates []int
	for newID, oldID := range order {
		acc[newID] = d.accept[oldID]
		if acc[newID] {
			accStates = append(accStates, newID)
		} else {
			nonAccStates = append(nonAccStates, newID)
		}
		oldBase := oldID * k
		newBase := newID * k
		for c := 0; c < k; c++ {
			trans[newBase+c] = remap[d.transitions[oldBase+c]]
		}
	}

	if len(accStates) == 0 {
		return Empty()
	}
	if len(nonAccStates) == 0 {
		return Universal()
	}

	// Build inverse transition lists indexed by (class * n + target).
	inv := make([][]int, k*n)
	for s := 0; s < n; s++ {
		base := s * k
		for c := 0; c < k; c++ {
			t := trans[base+c]
			inv[c*n+t] = append(inv[c*n+t], s)
		}
	}

	partitions := [][]int{accStates, nonAccStates}
	blockOf := make([]int, n)
	for _, s := range nonAccStates {
		blockOf[s] = 1
	}

	worklist := make([]int, 0, n)
	if len(accStates) <= len(nonAccStates) {
		worklist = append(worklist, 0)
	} else {
		worklist = append(worklist, 1)
	}

	touchedBlocks := make([]int, 0, 16)
	inX := make([][]int, 2)
	marked := make([]bool, n)

	for len(worklist) > 0 {
		aIdx := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]

		// Copy the splitter block since splitting can mutate partitions[aIdx].
		splitter := append([]int(nil), partitions[aIdx]...)

		for c := 0; c < k; c++ {
			touchedBlocks = touchedBlocks[:0]
			cOff := c * n
			for _, t := range splitter {
				for _, s := range inv[cOff+t] {
					if marked[s] {
						continue
					}
					marked[s] = true
					b := blockOf[s]
					if len(inX[b]) == 0 {
						touchedBlocks = append(touchedBlocks, b)
					}
					inX[b] = append(inX[b], s)
				}
			}

			for _, b := range touchedBlocks {
				xs := inX[b]
				if len(xs) < len(partitions[b]) {
					rest := make([]int, 0, len(partitions[b])-len(xs))
					for _, s := range partitions[b] {
						if !marked[s] {
							rest = append(rest, s)
						}
					}

					var kept, moved []int
					if len(xs) <= len(rest) {
						kept, moved = rest, append([]int(nil), xs...)
					} else {
						kept, moved = append([]int(nil), xs...), rest
					}

					newB := len(partitions)
					partitions[b] = kept
					partitions = append(partitions, moved)
					inX = append(inX, nil)
					for _, s := range moved {
						blockOf[s] = newB
					}

					// Adding the smaller half preserves Hopcroft's invariant whether b is queued or not.
					worklist = append(worklist, newB)
				}
				for _, s := range xs {
					marked[s] = false
				}
				inX[b] = inX[b][:0]
			}
		}
	}

	// Ensure start state lives in block 0.
	startBlock := blockOf[0]
	if startBlock != 0 {
		partitions[0], partitions[startBlock] = partitions[startBlock], partitions[0]
		for _, s := range partitions[0] {
			blockOf[s] = 0
		}
		for _, s := range partitions[startBlock] {
			blockOf[s] = startBlock
		}
	}

	m := len(partitions)
	minTrans := make([]int, m*k)
	minAcc := make([]bool, m)
	for b := 0; b < m; b++ {
		rep := partitions[b][0]
		minAcc[b] = acc[rep]
		repBase := rep * k
		outBase := b * k
		for c := 0; c < k; c++ {
			minTrans[outBase+c] = blockOf[trans[repBase+c]]
		}
	}

	res := &DFA{
		numStates:   m,
		numClasses:  k,
		start:       0,
		classOf:     d.classOf,
		transitions: minTrans,
		accept:      minAcc,
	}
	return res.compactClasses()
}

// compactClasses merges byte equivalence classes that share identical transition columns.
func (d *DFA) compactClasses() *DFA {
	if d.numClasses <= 1 {
		return d
	}

	colKey := make([]byte, d.numStates*4)
	seen := make(map[string]int, d.numClasses)
	oldToNew := make([]int, d.numClasses)
	keptOld := make([]int, 0, d.numClasses)

	for c := 0; c < d.numClasses; c++ {
		for s := 0; s < d.numStates; s++ {
			v := uint32(d.transitions[s*d.numClasses+c])
			off := s * 4
			colKey[off] = byte(v)
			colKey[off+1] = byte(v >> 8)
			colKey[off+2] = byte(v >> 16)
			colKey[off+3] = byte(v >> 24)
		}
		if id, ok := seen[string(colKey)]; ok {
			oldToNew[c] = id
		} else {
			id = len(keptOld)
			seen[string(colKey)] = id
			oldToNew[c] = id
			keptOld = append(keptOld, c)
		}
	}

	newK := len(keptOld)
	if newK == d.numClasses {
		return d
	}

	var newClassOf [AlphabetSize]uint8
	for i := 0; i < AlphabetSize; i++ {
		newClassOf[i] = uint8(oldToNew[d.classOf[i]])
	}

	newTrans := make([]int, d.numStates*newK)
	for s := 0; s < d.numStates; s++ {
		oldBase := s * d.numClasses
		newBase := s * newK
		for newC, oldC := range keptOld {
			newTrans[newBase+newC] = d.transitions[oldBase+oldC]
		}
	}

	return &DFA{
		numStates:   d.numStates,
		numClasses:  newK,
		start:       d.start,
		classOf:     newClassOf,
		transitions: newTrans,
		accept:      d.accept,
	}
}

// onlyEmpty reports whether L(d) == {""}.
func (d *DFA) onlyEmpty() bool {
	if !d.accept[d.start] {
		return false
	}
	// Check whether any non-empty string can reach an accepting state.
	visited := make([]bool, d.numStates)
	queue := make([]int, 0, d.numStates)
	base := d.start * d.numClasses
	for c := 0; c < d.numClasses; c++ {
		v := d.transitions[base+c]
		if !visited[v] {
			visited[v] = true
			queue = append(queue, v)
		}
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		if d.accept[u] {
			return false
		}
		uBase := u * d.numClasses
		for c := 0; c < d.numClasses; c++ {
			v := d.transitions[uBase+c]
			if !visited[v] {
				visited[v] = true
				queue = append(queue, v)
			}
		}
	}
	return true
}
