package main
import (
	"fmt"
	"os"
	"strings"
	"encoding/json"
	"sort"
	"strconv"
	"reflect"
	r2 "github.com/radareorg/r2pipe-go"
)

const (
        Success int	= 0
        Target		= 1
        Symbol		= 2
        Help		= 4
	Default		= 5
	None		= 6
)



type sysc struct{
	Addr	uint64
	Name	string
}
type res struct{
	Syscall	sysc
	Path	[]uint64
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
	Ref		vars_ref	`json: "ref"`
}
type vars_ref struct{
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
type xref_cache struct{
	Addr		uint64
	Xr		[]uint64
}


// field stack_var_.Spvars.Ref of type []main



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

func Getxrefs2(current uint64, functions []func_data) ([]uint64){
        var xrefs               []ref_
        var res                 []uint64;


	fmt.Println("Getxrefs2: ", current)
        for _, f := range functions  {
                if f.Offset==current {
                        xrefs=f.Callrefs
			fmt.Println("Getxrefs2: ", f.Offset, f.Name)
			break
                        }
                }

	fmt.Println("Getxrefs2: ", xrefs)
        for _, item := range xrefs  {
                if item.Type=="CODE" {
                        res=append(res,item.Addr)
                        }
                }
	 fmt.Println("Getxrefs2: ", res)
        return  res
}

func Getxrefs3(r2p *r2.Pipe, current uint64, cache *[]xref_cache) ([]uint64){
        var xrefs               []xref
        var res                 []uint64;

	for _, item := range *cache  {
                if item.Addr==current {
//			fmt.Println( "cache hit")
                        return item.Xr
                        }
                }
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
	*cache=append(*cache,xref_cache{current,res})
//	fmt.Println( "update cache ", len(*cache) )
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

func Symb2Addr(s string, funcs []func_data) (uint64){
        for _, f := range funcs {
                if strings.Contains(f.Name,s)  {
			if f.Name != s {
				fmt.Printf("Warning: provided symbol %s not found, using %s", s, f.Name)
	                        return f.Offset
				}
                	}
        	}
        return 0
}

func Symb2Addr_r(s string, r2p *r2.Pipe) (uint64){
	var f  []func_data
        buf, err := r2p.Cmd("afij "+ s)
        if err != nil {
                panic(err)
                }
	fmt.Println(buf)
	error := json.Unmarshal( []byte(buf), &f)
        if(error != nil){
                fmt.Printf("Error while parsing data: %s", error)
                }
	fmt.Println(f[0])
	return f[0].Offset
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

func sys_add(start uint64, end uint64, results *[]res, syscall_list []sysc, path []uint64){
	for _, s := range syscall_list {
		if s.Addr >= start && s.Addr <= end {
			*results=append(*results,res{s,path})
			return
			}
		}
}

/*
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
*/

func Navigate (r2p *r2.Pipe, current uint64, visited []uint64, results *[]res, syscall_list []sysc, functions []func_data, xr_cache *[]xref_cache){

//	fmt.Printf("0x%08x\n", current)
	Move(r2p, current)
//	xrefs1:=Getxrefs(r2p)
	xrefs3:=Getxrefs3(r2p, current, xr_cache)
//	xrefs2:=Getxrefs2(current, functions)
	path:=append(visited, current)
//	fmt.Println("current list ",xrefs)
	sys_add(current, Function_end(current, functions), results, syscall_list, path)
//	results:=checkfunction(current, targets)
	for _,xref := range(xrefs3) {
//			fmt.Println("current ", current, " visiting ", xref, " visited ",*visited," iteration ",i)
			if NotContained(visited,xref) {
				Navigate(r2p, xref, path, results, syscall_list, functions, xr_cache)
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

func print_help(fn string){
        fmt.Println("Syscall finder")
        fmt.Println("\t-s\tspecifies the symbol where the search starts")
        fmt.Println("\t-f\tspecifies library path")
        fmt.Println("\t-h\t\tthis help")
        fmt.Printf("\nusage: %s -f libc.so.6 -s malloc\n", fn)
}
func print_error(err_no int, fn0 string){
        switch err_no {
                case Target:
                        fmt.Println("File error")
			print_help(fn0)
                case Symbol:
                        fmt.Println("symbol error")
			print_help(fn0)
                case Help:
		case Default:
                        print_help(fn0)
                }
}



func main() {
	var visited		[]uint64
	var results		[]res
	var xr_cache		[]xref_cache
	var FileName		string="Empty"
	var SymbolTarget	string="Empty"

        arg_func:=None;
        for _, arg := range os.Args[1:] {
                switch arg {
                        case "-f":
//				fmt.Println("reach here Target")
                                arg_func=Target
                        case "-s":
//				fmt.Println("reach here Symbol")
                                arg_func=Symbol
                        case "-h":
//				fmt.Println("reach here Help")
                                print_help(os.Args[0])
				os.Exit(Help)
                        default:
//				fmt.Println("reach here default")
                                switch arg_func {
                                        case Target:
                                                FileName=arg
                                                if _, err := os.Stat(FileName); err != nil {
                                                        print_error(arg_func, os.Args[0])
                                                        os.Exit(arg_func)
                                                        }
                                        case Symbol:
                                                SymbolTarget = arg
					case Help:
						print_help(os.Args[0])
						os.Exit(Success)
                                        default:
                                                print_error(Default, os.Args[0])
                                                os.Exit(Default)
                                        }
                        }
                }
//	fmt.Println("reach here", os.Args[0])
	if FileName=="Empty" ||  SymbolTarget=="Empty" {
		print_error(Help, os.Args[0])
		os.Exit(Default)
		}

	r2p, err := r2.NewPipe(FileName)
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
	funcs_data := get_all_funcdata(r2p)

//	target2search:=Symb2Addr(SymbolTarget, funcs_data)
	target2search:=Symb2Addr_r(SymbolTarget, r2p)
	if target2search==0 {
		print_error(Symbol, os.Args[0])
		os.Exit(Symbol)
		}

	Navigate(r2p, target2search, visited, &results, get_syscalls(r2p), funcs_data, &xr_cache)
	fmt.Println(results)

//	fmt.Println(Function_info(505852, get_all_funcdata(r2p)))

}
