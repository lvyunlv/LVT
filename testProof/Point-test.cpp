#include "emp-aby/elgl/BLS12381Element.h"
using namespace std;
int main(){
    BLS12381Element::init();
    BLS12381Element a(1);
    BLS12381Element b(1);
    BLS12381Element c = a + b;
    cout << c << endl;

    std::stringstream os;
    c.pack(os);
    BLS12381Element d;
    d.unpack(os);
    if (c == d){
        cout << "Packing and unpacking works!" << endl;
    } else {
        cout << "Packing and unpacking failed!" << endl;
    }
    return 0;
}
