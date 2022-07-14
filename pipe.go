package main
import (
	"fmt"
	"strings"
	"encoding/json"
	"sort"
	"strconv"
	"reflect"
	r2 "github.com/radareorg/r2pipe-go"
)


type sysc struct{
	Addr	uint64;
	Name	string;
}

type func_data struct {
	Offset		uint64		`json:"offset"`
	Name		string		`json: "name"`
	Size		uint32		`json: "size"`
	Is_pure		string		`json: "is-pure"`
	Realsz		uint64		`json: "realsz"`
	Noreturn	bool		`json: "noreturn"`
	Stackframe	uint16		`json: "stackframe"`
	Calltype	string		`json: "calltype"`
	Cost		uint16		`json: "cost"`
	Cc		uint16		`json: "cc"`
	Bits		uint16		`json: "bits"`
	Type		string		`json: "type"`
	Nbbs		uint16		`json: "nbbs"`
	Is_lineal	bool		`json: "is-lineal"`
	Ninstrs		uint8		`json: "ninstrs"`
	Edges		uint8		`json: "edges"`
	Ebbs		uint8		`json: "ebbs"`
	Signature	string		`json: "signature"`
	Minbound	uint32		`json: "minbound"`
	Maxbound	uint32		`json: "maxbound"`
	Callrefs	[]ref_		`json: "callrefs"`
	Datarefs	[]uint64	`json: "datarefs"`
	Codexrefs	[]ref_		`json: "codexrefs"`
	Dataxrefs	[]uint64	`json: "dataxrefs"`
	Indegree	uint8		`json: "indegree"`
	Outdegree	uint8		`json: "outdegree"`
	Nlocals		uint8		`json: "nlocals"`
	Nargs		uint8		`json: "nargs"`
	Bpvars		[]stack_var_	`json: "bpvars"`
	Spvars		[]stack_var_	`json: "spvars"`
	Regvars		[]reg_var_	`json: "regvars"`
	Difftype	string		`json: "difftype"`
}
type ref_ struct{
	Addr		uint64		`json: "addr"`
	Type		string		`json: "type"`
	At		uint64		`json: "at"`
}
type stack_var_ struct{
	Name		string		`json: "name"`
	Kind		string		`json: "kind"`
	Type		string		`json: "type"`
	Ref		[]var_ref_	`json: "ref"`
}
type	var_ref_ struct{
	Base		string		`json: "base"`
	Offset		uint32		`json: "offset"`
}
type reg_var_ struct{
	Name		string		`json: "name"`
	Kind		string		`json: "kind"`
	Type		string		`json: "type"`
	Ref		[]string	`json: "ref"`
}
type xref struct{
	Type		string		`json: "type"`
	From		uint64		`json: "from"`
	To		uint64		`json: "to"`
}






type fref struct{
	Addr		uint64
	Name		string
}
type results struct{
	Addr		uint64
	Name		string
	Path		[]fref
}


func Move(r2p *r2.Pipe,current uint64){
	_, err := r2p.Cmd("s "+ strconv.FormatUint(current,10))
	if err != nil {
		panic(err)
		}
}

func Getxrefs(r2p *r2.Pipe) ([]uint64){
	var xrefs		[]xref
	var res			[]uint64;

	buf, err := r2p.Cmd("afxj")
	if err != nil {
		panic(err)
		}
	error := json.Unmarshal( []byte(buf), &xrefs)
	if(error != nil){
		fmt.Printf("Error while parsing data: %s", error)
		}
	for _, item := range xrefs  {
		if item.Type=="CALL" {
			res=append(res,item.To)
			}
		}
	return  res
}

/*
func checkfunction(r2p *Pipe, current uint64, targets []uint64){
	buf, err := r2p.Cmd("/as")
	if err != nil {
		panic(err)
		}

}*/
func Function_end(current uint64, funcs []func_data) (end uint64){
        for _, f := range funcs {
                if f.Offset == current {
                        return uint64(f.Size)+current
                }
        }
        return 0
}

func convertSliceToInterface(s interface{}) (slice []interface{}) {
	v := reflect.ValueOf(s)
	if v.Kind() != reflect.Slice {
		return nil
	}

	length := v.Len()
	slice = make([]interface{}, length)
	for i := 0; i < length; i++ {
		slice[i] = v.Index(i).Interface()
	}

	return slice
}

func NotContained(s interface{}, e interface{}) bool {
	slice := convertSliceToInterface(s)

	for _, a := range slice {
		if a == e {
			return false
		}
	}
	return true
}

func sys_add(start uint64, end uint64, results *[]sysc, syscall_list []sysc){
	for _, s := range syscall_list {
		if s.Addr >= start && s.Addr <= end {
			*results=append(*results,s)
			return
			}
		}
}


func Navigate (r2p *r2.Pipe, current uint64, visited *[]uint64, results *[]sysc, syscall_list []sysc, functions []func_data){
//	fmt.Printf("0x%08x\n", current)
	Move(r2p, current)
	xrefs:=Getxrefs(r2p)
//	fmt.Println("current list ",xrefs)
	(*visited)=append(*visited, current)
	sys_add(current, Function_end(current, functions), results, syscall_list)
//	results:=checkfunction(current, targets)
	for _,xref := range(xrefs) {
//			fmt.Println("current ", current, " visiting ", xref, " visited ",*visited," iteration ",i)
			if NotContained(*visited,xref) {
				Navigate(r2p, xref, visited, results, syscall_list, functions)
				}
		}
}

func init_fw(r2p *r2.Pipe){

	fmt.Println("Initializing Radare framework")
	_, err := r2p.Cmd("aaa")
	if err != nil {
		panic(err)
		}
	fmt.Println("Addirional functions analysis")
	_, err = r2p.Cmd("aaf")
	if err != nil {
		panic(err)
		}
}
func get_syscalls(r2p *r2.Pipe) ([]sysc){
	var smap	[]sysc

	_, err := r2p.Cmd("aei")
	if err != nil {
		panic(err)
		}
	buf, err := r2p.Cmd("/as")
	if err != nil {
		panic(err)
		}
	temp := strings.Split(buf,"\n")
	for _, line := range temp {
		temp2 := strings.Split(line," ")
		num, err := strconv.ParseInt(strings.Replace(temp2[0], "0x", "", -1) , 16, 64)
		if err != nil {
 			panic(err)
			 }
		smap = append(smap, sysc{uint64(num),temp2[1]})
		}
	sort.SliceStable(smap, func(i, j int) bool {return smap[i].Addr < smap[j].Addr})
	return smap
}



func get_all_funcdata(r2p *r2.Pipe)([]func_data){
	var functions	[]func_data

	buf, err := r2p.Cmd("aflj")
	if err != nil {
		panic(err)
		}
	error := json.Unmarshal( []byte(buf), &functions)
	if(error != nil){
		fmt.Printf("Error while parsing data: %s", error)
		}
	sort.SliceStable(functions, func(i, j int) bool {return functions[i].Offset < functions[j].Offset})
	return functions
}

func main() {
	var visited []uint64
	var results []sysc

	r2p, err := r2.NewPipe("./libc.so.aarch64")
	if err != nil {
		panic(err)
		}
	defer r2p.Close()
	init_fw(r2p)
//	fmt.Println(smap)

//	fmt.Println(functions)
//	Move(r2p, 505852)//sym.malloc
//	xr:=Getxrefs(r2p)
//	fmt.Println(xr)

	Navigate(r2p, 505852, &visited, &results, get_syscalls(r2p), get_all_funcdata(r2p))
	fmt.Println(results)

//	fmt.Println(Function_info(505852, get_all_funcdata(r2p)))

}
