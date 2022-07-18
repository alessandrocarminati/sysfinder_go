package main
import (
	"fmt"
	"os"
	"log"
	"time"
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



type sysc struct {
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
	Size		uint64		`json: "size"`
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
	Ninstrs		uint16		`json: "ninstrs"`
	Edges		uint16		`json: "edges"`
	Ebbs		uint8		`json: "ebbs"`
	Signature	string		`json: "signature"`
	Minbound	uint32		`json: "minbound"`
	Maxbound	uint32		`json: "maxbound"`
	Callrefs	[]ref_		`json: "callrefs"`
	Datarefs	[]uint64	`json: "datarefs"`
	Codexrefs	[]ref_		`json: "codexrefs"`
	Dataxrefs	[]uint64	`json: "dataxrefs"`
	Indegree	uint16		`json: "indegree"`
	Outdegree	uint16		`json: "outdegree"`
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
	Offset		int32		`json: "offset"`
}
type reg_var_ struct{
	Name		string		`json: "name"`
	Kind		string		`json: "kind"`
	Type		string		`json: "type"`
	Ref		string		`json: "ref"`
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

type fref struct{
	Addr		uint64
	Name		string
}
type results struct{
	Addr		uint64
	Name		string
	Path		[]fref
}

var ts_Move		int64 =0
var ts_Getxrefs		int64 =0
var ts_get_all_funcdata	int64 =0
var ts_get_syscalls	int64 =0
var ts_init_fw		int64 =0
var ts_removeDuplicate	int64 =0
var ts_sys_add		int64 =0
var ts_NotContained	int64 =0
var ts_Symb2Addr_r	int64 =0

func update_prof_stat(ts_in int64, ts_global *int64){
	ts_out:=time.Now().UnixNano()
	*ts_global+= (ts_out - ts_in)
}


func Move(r2p *r2.Pipe,current uint64){
	x:=time.Now().UnixNano()
	defer update_prof_stat(x, &ts_Move)


	_, err := r2p.Cmd("s "+ strconv.FormatUint(current,10))
	if err != nil {
		panic(err)
		}
}

func Getxrefs(r2p *r2.Pipe, current uint64, cache *[]xref_cache) ([]uint64){
        var xrefs               []xref
        var res                 []uint64;
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_Getxrefs)

	for _, item := range *cache  {
                if item.Addr==current {
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
                res=append(res,item.To)
                }
	*cache=append(*cache,xref_cache{current,res})
        return  res
}

func Symb2Addr_r(s string, r2p *r2.Pipe) (uint64){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_Symb2Addr_r)

	var f  []func_data
        buf, err := r2p.Cmd("afij "+ s)
        if err != nil {
                panic(err)
                }
	error := json.Unmarshal( []byte(buf), &f)
        if(error != nil){
                fmt.Printf("Error while parsing data: %s", error)
                }
	if len(f)>0 {
		return f[0].Offset
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
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_NotContained)

	slice := convertSliceToInterface(s)

	for _, a := range slice {
		if a == e {
			return false
		}
	}
	return true
}

func sys_add(r2p *r2.Pipe, start uint64, funcs []func_data, results *[]res, syscall_list []sysc, path []uint64) (int){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_sys_add )

	type bloc struct {
       		Start	uint64
        	End	uint64
	}
	type rad_bloc struct {
		Jump	uint64	`json: "jump"`
		Fail	uint64	`json: "fail"`
		Opaddr	uint64	`json: "opaddr"`
		Addr	uint64	`json: "addr"`
		Size	uint64	`json: "size"`
		Inputs	uint8	`json: "inputs"`
		Outputs	uint8	`json: "outputs"`
		ninstr	uint16	`json: "ninstr"`
		traced	bool	`json: "traced"`
	}



	var blocs	[]bloc
	var rad_blocs	[]rad_bloc

        for _, f := range funcs {
                if f.Offset == start {
			if f.Size==f.Realsz {
	                        blocs=append(blocs,bloc{f.Offset, f.Offset+f.Size})
				} else {
			        buf, err := r2p.Cmd("afbj")
				if err != nil {
					panic(err)
					 }
				error := json.Unmarshal( []byte(buf), &rad_blocs)
				if(error != nil){
					fmt.Printf("Error while parsing data: %s", error)
					}
				for _,b := range rad_blocs {
					blocs=append(blocs, bloc{b.Addr,b.Addr+b.Size})
					}
				}
                }
        }

	tmp:=0
	for _, s := range syscall_list {
		for _, b := range blocs {
			if s.Addr >= b.Start && s.Addr <= b.End {
				*results=append(*results,res{s,path})
				tmp++
				}
			}
		}
	return tmp
}

func removeDuplicate(intSlice []uint64) []uint64 {
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_removeDuplicate )

	allKeys := make(map[uint64]bool)
	list := []uint64{}
	for _, item := range intSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
			}
		}
	return list
}

func remove_non_func(list []uint64, functions []func_data) []uint64 {

	res := []uint64{}
	for _, item := range list {
		if is_func(item, functions) {
			res = append(res, item)
			}
		}
	return res
}

func sSE(a, b []uint64) bool {
	if len(a) != len(b) {
		return true
	}
	for i, v := range a {
		if v != b[i] {
			return true
		}
	}
	return false
}

func Navigate (r2p *r2.Pipe, current uint64, visited *[]uint64, old_path []uint64, results *[]res, syscall_list []sysc, functions []func_data, xr_cache *[]xref_cache){

	Move(r2p, current)
	xrefs:=remove_non_func(removeDuplicate(Getxrefs(r2p, current, xr_cache)),functions)

	*visited=append(*visited, current)
	path:=append(old_path, current);
	_=sys_add(r2p, current, functions, results, syscall_list, path)
	for _,xref := range(xrefs) {
			if NotContained(*visited,xref) {
				Navigate(r2p, xref, visited, path, results, syscall_list, functions, xr_cache)
				}
		}
}

func init_fw(r2p *r2.Pipe){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_init_fw )

	l := log.New(os.Stderr, "", 0)

	l.Println("Initializing Radare framework")
        _, err := r2p.Cmd("e anal.nopskip=false")
        if err != nil {
                panic(err)
                }
	_, err = r2p.Cmd("aaa")
	if err != nil {
		panic(err)
		}
	l.Println("Addirional functions analysis")
	_, err = r2p.Cmd("aaf")
	if err != nil {
		panic(err)
		}
	l.Println("analisys")



}
func get_syscalls(r2p *r2.Pipe) ([]sysc){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_get_syscalls )

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

func is_func(addr uint64, list []func_data) (bool){
	i := sort.Search(len(list), func(i int) bool { return list[i].Offset >= addr })
	if i < len(list) && list[i].Offset == addr {
		return true;
		}
	return false
}

func get_all_funcdata(r2p *r2.Pipe)([]func_data){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_get_all_funcdata )

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
        fmt.Println("\t-p\tprint profiler data")
        fmt.Println("\t-t\tprint terse data")
        fmt.Println("\t-h\tthis help")
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
			fallthrough
		case Default:
                        print_help(fn0)
                }
}

func print_stats(){
	fmt.Println(ts_Move," Move ticks")
	fmt.Println(ts_Getxrefs, " Getxrefs ticks")
	fmt.Println(ts_get_all_funcdata, " get_all_funcdata ticks")
	fmt.Println(ts_get_syscalls, " get_syscalls ticks")
	fmt.Println(ts_init_fw, " init_fw ticks")
	fmt.Println(ts_removeDuplicate, " removeDuplicate ticks")
	fmt.Println(ts_sys_add, " sys_add ticks")
	fmt.Println(ts_NotContained, " NotContained ticks")
	fmt.Println(ts_Symb2Addr_r, " Symb2Addr_r ticks")
}

func Addr2Sym(addr uint64, list []func_data) (string){
        i := sort.Search(len(list), func(i int) bool { return list[i].Offset >= addr })
        if i < len(list) && list[i].Offset == addr {
                return list[i].Name;
                }
        return "Unknown"
}

func produce_terse(results []res) []string {
        allKeys := make(map[string]bool)
        list := []string{}
        for _, item := range results {
                if _, value := allKeys[item.Syscall.Name]; !value {
                        allKeys[item.Syscall.Name] = true
                        list = append(list, item.Syscall.Name)
                        }
                }
        return list
}


func print_results(results []res, terse bool, list []func_data){

	if !terse {
		for i, item := range results {
			fmt.Printf("%04d:0x%08x %s ->[ ", i, item.Syscall.Addr, item.Syscall.Name)
			for _,x :=range item.Path {
				fmt.Printf("%s(0x%08x), ", Addr2Sym(x,list), x)
				}
			fmt.Printf("]\n")
			}
		}
	fmt.Println(produce_terse(results))
	fmt.Println(len(produce_terse(results)))
}

func main() {
	var visited		[]uint64
	var results		[]res
	var xr_cache		[]xref_cache
	var FileName		string="Empty"
	var SymbolTarget	string="Empty"

        arg_func:=None
	profiler:=false
	terse:=false
        for _, arg := range os.Args[1:] {
                switch arg {
                        case "-f":
                                arg_func=Target
                        case "-s":
                                arg_func=Symbol
			case "-p":
				profiler=true
			case "-t":
				terse=true
                        case "-h":
                                print_help(os.Args[0])
				os.Exit(Help)
                        default:
                                switch arg_func {
                                        case Target:
                                                FileName=arg
                                                if _, err := os.Stat(FileName); err != nil {
                                                        print_error(arg_func, os.Args[0])
                                                        os.Exit(arg_func)
                                                        }
						arg_func=None
                                        case Symbol:
                                                SymbolTarget = arg
						arg_func=None
					case Help:
						print_help(os.Args[0])
						os.Exit(Success)
                                        default:
                                                print_error(Default, os.Args[0])
                                                os.Exit(Default)
                                        }
                        }
                }
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
	funcs_data := get_all_funcdata(r2p)

	target2search:=Symb2Addr_r(SymbolTarget, r2p)
	if target2search==0 {
		print_error(Symbol, os.Args[0])
		os.Exit(Symbol)
		}
	Navigate(r2p, target2search, &visited, nil, &results, get_syscalls(r2p), funcs_data, &xr_cache)
	print_results(results, terse, funcs_data)
	if profiler {
		print_stats()
		}

}
