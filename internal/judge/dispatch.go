// SPDX-License-Identifier: MIT
package judge

// One nonce per question, and the order a free worker takes calls in (P-080).
//
// At samples k a question is the same request sent k times. Under a nonce per call the k requests
// shared no prefix longer than the pass's first sentence, so an endpoint's prompt cache (OpenAI's
// minimum is a 1,024-token identical prefix) could never serve a repeat. With one nonce per
// question the k requests are byte-identical; a repeat that is sent after its first was answered
// can be served from the prefix the first just paid for.
//
// Sharing the nonce keeps the barrier (spec §5.2): the scanned content is fixed before the nonce
// is drawn and never sees it, and no reply is fed into another sample's request, so a nonce shared
// by the k requests of one question is as unguessable to that content as k different ones. A
// re-ask (P-069) still draws its own (requestNonce); triage is one call and draws per call.

// withQuestionNonces returns a copy of tasks where each judge question's samples carry one nonce
// of their own. A draw that fails leaves the field empty: the client then draws per call and fails
// the call if it cannot, so there is never a guessable barrier (newNonce). tasks is not modified.
func withQuestionNonces(tasks []task) []task {
	out := append([]task(nil), tasks...)
	nonces := map[int]string{}
	for i := range out {
		if out[i].kind != taskJudge {
			continue
		}
		n, ok := nonces[out[i].group]
		if !ok {
			n, _ = newNonce() // "" on failure: the client's own draw reports it
			nonces[out[i].group] = n
		}
		out[i].req.Nonce = n
	}
	return out
}

// dispatchQueue decides which task a free worker takes next. A question's first sample is ready
// at once; its other samples wait until the first finished, so they reach the endpoint after the
// prefix they share is cached. They wait only while there is other work: a worker that would
// otherwise sit idle takes the earliest question's waiting samples instead. A run with more
// workers than calls (a check of one skill) therefore sends every needed call at once, as it did
// before the nonce was shared, and a busy run never leaves a worker idle that the old order kept
// busy — the queue changes which ready call a worker takes, never how many are in flight.
//
// With one worker the order is the table order, as before: a first finishes before anything
// else is taken, and its samples are next. Results are written by table index whatever the order
// (invariant #6).
//
// Not every sample is needed (P-103). A finding escalates with majority(n) votes, so once the first
// n−majority(n)+1 samples of a question all came back clean, the rest cannot reach the bar between
// them and nothing they say can make the question escalate. Those first samples are the question's
// needed ones and go out as above. The rest are conditional: they wait for an answer that is not
// clean, which releases them like a finished first releases its samples, and are settled — never
// sent — once every needed sample came back clean. An idle worker does not take a conditional
// sample: P-080 refused a wait that saved nothing, while this wait is what saves the call.
type dispatchQueue struct {
	released []int         // samples whose first finished (or that were released early), in that order
	ready    []int         // firsts, triage and single questions, in table order
	waiting  map[int][]int // first sample's index → its question's other needed samples, until released
	order    []int         // firsts whose samples may still be waiting, in table order

	question    map[int]int   // a sample of a question that has conditional samples → its first's index
	conditional map[int][]int // first → its question's conditional samples, until the question is decided
	unanswered  map[int]int   // first → its question's needed samples not yet finished clean
	settled     []int         // samples no answer could have changed, never to be taken (P-103)
}

func newDispatchQueue(tasks []task, samples int) *dispatchQueue {
	q := &dispatchQueue{waiting: map[int][]int{}, question: map[int]int{}, conditional: map[int][]int{},
		unanswered: map[int]int{}}
	needed := neededSamples(samples)
	first := map[int]int{} // judge group → index of its first sample
	position := map[int]int{}
	for i, t := range tasks {
		if t.kind != taskJudge {
			q.ready = append(q.ready, i)
			continue
		}
		f, ok := first[t.group]
		pos := position[t.group]
		position[t.group]++
		switch {
		case !ok:
			first[t.group] = i
			q.ready = append(q.ready, i)
			continue
		case pos < needed:
			if len(q.waiting[f]) == 0 {
				q.order = append(q.order, f)
			}
			q.waiting[f] = append(q.waiting[f], i)
		default:
			q.conditional[f] = append(q.conditional[f], i)
		}
	}
	// Only a question that has a conditional sample has anything to decide. Its needed samples are
	// its first and the samples waiting on it (a group the budget cut short has none to settle).
	for f := range q.conditional {
		q.question[f] = f
		for _, i := range q.waiting[f] {
			q.question[i] = f
		}
		q.unanswered[f] = 1 + len(q.waiting[f])
	}
	return q
}

// neededSamples is how many samples of a question go out whatever they say: the fewest whose all
// being clean leaves the rest unable to reach majority(samples) between them.
func neededSamples(samples int) int { return samples - majority(samples) + 1 }

// next returns the task a free worker should take, and false when no task can be taken now: every
// task was taken, or what is left are conditional samples waiting for their question's answers.
func (q *dispatchQueue) next() (int, bool) {
	if len(q.released) == 0 && len(q.ready) == 0 {
		q.releaseEarliest()
	}
	switch {
	case len(q.released) > 0:
		i := q.released[0]
		q.released = q.released[1:]
		return i, true
	case len(q.ready) > 0:
		i := q.ready[0]
		q.ready = q.ready[1:]
		return i, true
	}
	return 0, false
}

// finished records that task i completed, answered or not, and whether its answer was clean, and
// returns how many samples that settled. If i was a first whose samples still wait, they become the
// next to be taken. A failed first releases them the same way — there is nothing to gain by holding
// them, and they are the question's remaining votes. An answer that is not clean (a failure
// included) decides its question: its conditional samples are released. The last needed sample of
// a question coming back clean settles them.
func (q *dispatchQueue) finished(i int, clean bool) int {
	q.release(i)
	f, ok := q.question[i]
	if !ok {
		return 0
	}
	delete(q.question, i)
	rest, open := q.conditional[f]
	if !open {
		return 0 // already decided by an earlier answer that was not clean
	}
	if !clean {
		q.released = append(q.released, rest...)
		delete(q.conditional, f)
		delete(q.unanswered, f)
		return 0
	}
	q.unanswered[f]--
	if q.unanswered[f] > 0 {
		return 0
	}
	q.settled = append(q.settled, rest...)
	delete(q.conditional, f)
	delete(q.unanswered, f)
	return len(rest)
}

// releaseEarliest releases the samples of the earliest question that still has some waiting.
func (q *dispatchQueue) releaseEarliest() {
	for len(q.order) > 0 {
		f := q.order[0]
		if _, ok := q.waiting[f]; ok {
			q.release(f)
			return
		}
		q.order = q.order[1:]
	}
}

func (q *dispatchQueue) release(first int) {
	samples, ok := q.waiting[first]
	if !ok {
		return
	}
	delete(q.waiting, first)
	q.released = append(q.released, samples...)
}
