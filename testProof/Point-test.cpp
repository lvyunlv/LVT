#include "libelgl/elgl/BLS12381Element.h"
using namespace std;
int main(){
    BLS12381Element::init();
    BLS12381Element a(1);
    BLS12381Element b(1);
    BLS12381Element c = a + b;

    std::stringstream os;
    c.pack(os);
    a.pack(os);
    os.seekg(0);
    BLS12381Element d;
    d.unpack(os);
    if (c == d){
        cout << "Packing and unpacking works!" << endl;
    } else {
        cout << "Packing and unpacking failed!" << endl;
    }

    BLS12381Element e;
    e.unpack(os);
    if (b == e){
        cout << "Packing and unpacking works!" << endl;
    } else {
        cout << "Packing and unpacking failed!" << endl;
    }
    return 0;
}
