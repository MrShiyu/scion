package digest

import (
	"hash/fnv"
	"math"
)

//this is an implementation of blocked bloom filter

//the specification of the blocked bloom filter
type BloomFilter_spec struct {
	Capacity   int // n: Number of items in the filter
	NumHashes  int // k: Number of hash functions -> best to set it k = 0.693(ln2) m/n
	NumBits    int // m: Number of bits in each block of the filter
	numBuckets int // numBuckets := NumBits / 32, each bucket contains 32 bits (32 hash position)
	numBlocks  int // N: number of blocks in a blocked filter
}

//the structure of each one block
type BloomFilter struct {
	state []uint32
}

//the structure of one blocked filter, which consists of two parts: blocks of filter, and a specification
type BlockedFilter struct {
	filter []BloomFilter
	spec   BloomFilter_spec
}

//hash function used within each block, can be used to generate different hash functions
func hashFNV1a(input []byte) (uint32, uint32) {
	hash := fnv.New64a()
	hash.Write(input)
	value64 := hash.Sum64()
	return uint32(value64 & 0xFFFFFFFF), uint32(value64 >> 32) //getting the first 32 bits, and the last 32 bits of the hash value
}

//hash function used for determining which block to insert
func hashFNV(input []byte) uint32 {
	hash := fnv.New32()
	hash.Write(input)
	return hash.Sum32()
}

//calculate the bit to set inside each block, called by function Add
func (set *BloomFilter) setBit(index, numBuckets int) {
	bucket := (index / 32) % numBuckets //use 32 here because in the state field we use uint32
	offset := index % 32
	set.state[bucket] = set.state[bucket] | (1 << uint(offset))
}

//test if the bit is set inside each block, called by function Check
func (set *BloomFilter) testBit(index, numBuckets int) int {
	bucket := (index / 32) % numBuckets
	offset := index % 32
	if set.state[bucket]&(1<<uint(offset)) != 0 {
		return 1
	}
	return 0

}

// Add data to one block, called by function BlockAdd
func (set *BloomFilter) add(input []byte, NumHashes, NumBits, NumBuckets int) {
	hashA, hashB := hashFNV1a(input)
	for i := 0; i < NumHashes; i++ {
		index := int((hashA + hashB*uint32(i))) % NumBits
		//simulate different hash functions by doing gi(x) = h1(x) + ih2(x).
		set.setBit(index, NumBuckets)
	}
}

//This is the Add function on the API of block bloom filter
//add data to the whole block filter,it checks which block to insert, then call function Add
func (set *BlockedFilter) BlockAdd(input []byte) {
	hash := hashFNV(input)
	blockIndex := hash % uint32(set.spec.numBlocks)
	set.filter[blockIndex].add(input, set.spec.NumHashes, set.spec.NumBits, set.spec.numBuckets)
}

// Check if data exist in one block, called by function BlockCheck
func (set *BloomFilter) check(input []byte, NumHashes int, NumBits int, NumBuckets int) bool {
	hashA, hashB := hashFNV1a(input)
	for i := 0; i < NumHashes; i++ {
		index := int((hashA + hashB*uint32(i))) % NumBits
		if set.testBit(index, NumBuckets) != 1 {
			return false
		}
	}
	return true
}

//Check if data is in the whole block filter, it decides which block it should check, then calls function Check
func (set *BlockedFilter) BlockCheck(input []byte) bool {
	hash := hashFNV(input)
	blockIndex := hash % uint32(set.spec.numBlocks)
	return set.filter[blockIndex].check(input, set.spec.NumHashes, set.spec.NumBits, set.spec.numBuckets)
}

//reset the filter to all 0
func (set *BlockedFilter) Reset() {
	for i := 0; i < set.spec.numBlocks; i++ {
		for j := 0; j < set.spec.numBuckets; j++ {
			set.filter[i].state[j] = uint32(0)
		}
	}
}

//initialize a new block bloom filter. Args: capacity: the number of items to be inserted in this filter
//size: the number of bits in this filter, expressed in KB
//FalsePositiveRate can be calculated: e^(size(in bit)*log(1/(2^log2))/capacity)
func NewBlockedBloomFilter(numHashes, size int) BlockedFilter {
	//numBits: hardcoded as 64bytes(64*8 bits)
	NumBits := 64 * 8
	//size: the size of the whole block filter = m*N, unit: KB
	numBlocks := (size * 8192) / NumBits
	//each bucket is one uint32, used for storing bits
	numBuckets := NumBits / 32
	//numHashes can also be set as independent variable, while capacity dependent. Depending on the demand
	capacity := int(math.Floor(float64((NumBits * numBlocks / numHashes)) * math.Log(2)))

	newSpec := BloomFilter_spec{
		Capacity:   capacity,
		NumHashes:  numHashes,
		NumBits:    NumBits,
		numBuckets: numBuckets,
		numBlocks:  numBlocks}
	newBlocked := make([]BloomFilter, numBlocks)
	for i := 0; i < numBlocks; i++ {
		newBlocked[i] = BloomFilter{
			state: make([]uint32, uint(numBuckets))}
	}

	return BlockedFilter{
		filter: newBlocked,
		spec:   newSpec}

}
