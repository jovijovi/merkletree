package v2

type INode interface {
	BuildTree() error
}

type Node struct {
	Hash   []byte
	Degree int
}

type Leaf struct {
}

type Leaves struct {
	Leaves []Leaf
}

func (i *Leaves) BuildTree() error {
	return nil
}

type IntermediateNode struct {
}

type Root struct {
}
