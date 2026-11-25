package automata

import "sort"

// byteRank assigns lower (preferred) ranks to readable URL path characters:
// a-z, 0-9, '/', '.', '-', '_', A-Z, then remaining printable ASCII.
var byteRank = buildByteRank()

func buildByteRank() [AlphabetSize]uint8 {
	var rank [AlphabetSize]uint8
	var order []byte

	for ch := byte('a'); ch <= 'z'; ch++ {
		order = append(order, ch)
	}
	for ch := byte('0'); ch <= '9'; ch++ {
		order = append(order, ch)
	}
	order = append(order, '/', '.', '-', '_')
	for ch := byte('A'); ch <= 'Z'; ch++ {
		order = append(order, ch)
	}

	assigned := make([]bool, AlphabetSize)
	r := uint8(0)
	for _, ch := range order {
		idx := int(ch - MinByte)
		rank[idx] = r
		assigned[idx] = true
		r++
	}
	for i := 0; i < AlphabetSize; i++ {
		if !assigned[i] {
			rank[i] = r
			r++
		}
	}
	return rank
}

// ShortestWitness returns a shortest string accepted by the DFA via BFS.
// Equivalence class representatives prefer readable URL characters (a-z, 0-9, /, ., -, _).
func (d *DFA) ShortestWitness() (string, bool) {
	if d.numStates == 0 {
		return "", false
	}
	if d.accept[d.start] {
		return "", true
	}

	// Pick the best-ranked representative byte for each equivalence class.
	classRep := make([]byte, d.numClasses)
	classBestRank := make([]uint8, d.numClasses)
	for c := range classBestRank {
		classBestRank[c] = 255
	}
	for i := 0; i < AlphabetSize; i++ {
		c := int(d.classOf[i])
		if byteRank[i] < classBestRank[c] {
			classBestRank[c] = byteRank[i]
			classRep[c] = MinByte + byte(i)
		}
	}

	classOrder := make([]int, d.numClasses)
	for c := range classOrder {
		classOrder[c] = c
	}
	sort.Slice(classOrder, func(i, j int) bool {
		return classBestRank[classOrder[i]] < classBestRank[classOrder[j]]
	})

	visited := make([]bool, d.numStates)
	parent := make([]int, d.numStates)
	parentByte := make([]byte, d.numStates)
	queue := make([]int, 0, d.numStates)

	visited[d.start] = true
	parent[d.start] = -1
	queue = append(queue, d.start)

	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		base := u * d.numClasses

		for _, c := range classOrder {
			v := d.transitions[base+c]
			if visited[v] {
				continue
			}
			visited[v] = true
			parent[v] = u
			parentByte[v] = classRep[c]

			if d.accept[v] {
				return reconstructWitness(v, parent, parentByte), true
			}
			queue = append(queue, v)
		}
	}
	return "", false
}

func reconstructWitness(goal int, parent []int, parentByte []byte) string {
	var rev []byte
	for cur := goal; parent[cur] != -1; cur = parent[cur] {
		rev = append(rev, parentByte[cur])
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return string(rev)
}
