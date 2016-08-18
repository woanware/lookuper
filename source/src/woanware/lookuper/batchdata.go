package main

// Holds the "batch" struc and associated methods

// Encapsulates a batch of data that is used by the "worker" objects
type BatchData struct {
	Items []string
}

// Adds an array of string data to the "batchdata" items
func (b *BatchData) Add(data []string) {
	for _, d := range data {
		if len(d) > 0 {
			b.Items = append(b.Items, d)
		}
	}
}

// Adds a single string to the "batchdata" items
func (b *BatchData) AddData(data string) {
	if len(data) > 0 {
		b.Items = append(b.Items, data)
	}
}
