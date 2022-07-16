package main
import (
	"fmt"
	"os"
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



type sysc struct{
	Addr	uint64
	Name	string
}
type res struct{
	Syscall	sysc
	Path	[]string
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
var ts_Function_end 	int64 =0

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
                if item.Type=="CALL" {
                        res=append(res,item.To)
                        }
                }
	*cache=append(*cache,xref_cache{current,res})
        return  res
}

func Function_end(current uint64, funcs []func_data) (end uint64){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_Function_end)

        for _, f := range funcs {
                if f.Offset == current {
                        return uint64(f.Size)+current
                }
        }
        return 0
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

func sys_add(start uint64, end uint64, results *[]res, syscall_list []sysc, path []uint64){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_sys_add )

	for _, s := range syscall_list {
		if s.Addr >= start && s.Addr <= end {
			*results=append(*results,res{s,path_s})
			return
			}
		}
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

func Navigate (r2p *r2.Pipe, current uint64, visited []uint64, results *[]res, syscall_list []sysc, functions []func_data, xr_cache *[]xref_cache){

	Move(r2p, current)
	xrefs:=removeDuplicate(Getxrefs(r2p, current, xr_cache))
	path:=append(visited, current)
	sys_add(current, Function_end(current, functions), results, syscall_list, path)
	for _,xref := range(xrefs) {
			if NotContained(visited,xref) {
				Navigate(r2p, xref, path, results, syscall_list, functions, xr_cache)
				}
		}
}

func init_fw(r2p *r2.Pipe){
        x:=time.Now().UnixNano()
        defer update_prof_stat(x, &ts_init_fw )


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
	fmt.Println(ts_Function_end, " Function_end ticks")
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
                                arg_func=Target
                        case "-s":
                                arg_func=Symbol
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

	Navigate(r2p, target2search, visited, &results, get_syscalls(r2p), funcs_data, &xr_cache)
	fmt.Println(results)
	print_stats()

}
