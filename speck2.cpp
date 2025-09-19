#include <iostream>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <random>
#include <sstream>
#define Rounds 32
using namespace std;

uint64_t rotr64(uint64_t num, int swift) {
    return (num >> swift) | (num << (64 - swift));
}

uint64_t rotl64(uint64_t num, int swift) {
    return (num << swift) | (num >> (64 - swift));
}


uint64_t string_to_uint64(const string& str, size_t offset) {
    uint64_t result = 0;
    size_t copy_len = min(str.size() - offset, static_cast<size_t>(8));
    for (size_t i = 0; i < copy_len; ++i) {
        result |= static_cast<uint64_t>(str[offset + i]) << (8 * i);
    }
    return result;
}

void str_to_bin(const string& key, vector<uint64_t>& key_vec, const string& message, vector<uint64_t>& mes_vec) {

    key_vec.clear();
    mes_vec.clear();

    for (size_t i = 0; i < key.size(); i += 8) {
        key_vec.push_back(string_to_uint64(key, i));
    }

    for (size_t i = 0; i < message.size(); i += 8) {
        mes_vec.push_back(string_to_uint64(message, i));
    }
}

string blocks_to_str(const vector<uint64_t>& blocks) {
    string result;
    for (uint64_t block : blocks) {
        for (int j = 0; j < 8; ++j) {
            char c = static_cast<char>((block >> (8 * j)) & 0xFF);
            if (c != '\0') result += c;
        }
    }
    return result;
}

vector<uint64_t> keygen(uint64_t key_high, uint64_t key_low) {
    vector<uint64_t> keys;
    vector<uint64_t> l(32);
    
    l[0] = key_low;
    keys.push_back(key_high);
    
    for (int i = 0; i < 31; ++i) {
        l[i+1] = rotr64(l[i], 8) + keys[i];
        l[i+1] ^= i;
        keys.push_back(rotl64(l[i], 3) ^ l[i+1]);
    }
    
    return keys;
}

void speck_encrypt_round(uint64_t& left, uint64_t& right, uint64_t round_key) {
    right = rotr64(right, 8);
    right += left;
    right ^= round_key;
    left = rotl64(left, 3);
    left ^= right;
}

void speck_decrypt_round(uint64_t& left, uint64_t& right, uint64_t round_key) {
    left ^= right;
    left = rotr64(left, 3);
    
    right ^= round_key;
    right -= left;
    right = rotl64(right, 8);
}

void speck_encrypt_block(uint64_t& left, uint64_t& right, vector<uint64_t> round_keys) {
    for (int i=0; i<Rounds; i++) {
        speck_encrypt_round(left, right, round_keys[i]);
    }
}

void speck_decrypt_block(uint64_t& left, uint64_t& right, vector<uint64_t> round_keys) {
    for (int i=Rounds-1; i>=0; i--) {
        speck_decrypt_round(left, right, round_keys[i]);
    }
}

void cbc(uint64_t& left, uint64_t& right, uint64_t xor_left, uint64_t xor_right) {
    left ^= xor_left;
    right ^= xor_right;
}

// void cbc_decrypt(uint64_t& left, uint64_t& right, uint64_t xor_left, uint64_t xor_right){
//     left ^= xor_left;
//     right ^= xor_right;
// }

uint64_t crypt_random() {
    uint64_t a, b, k1, k2;
    random_device rd;
    a = rd();
    b = rd();
    k1 = rd();
    k2 = rd();
    vector<uint64_t> keys = keygen(k1, k2);
    speck_encrypt_block(a, b, keys);
    return a^b;
}

void encryption(vector<uint64_t>& mes_vec, vector<uint64_t>& key_vec, vector<uint64_t>& enc_vec) {
    int size = mes_vec.size();
    vector<uint64_t> round_keys;
    for (int i = 0; i < size; i+=2) {
        round_keys = keygen(key_vec[i], key_vec[i+1]);
        cbc(mes_vec[i], mes_vec[i+1], enc_vec[i], enc_vec[i+1]);
        speck_encrypt_block(mes_vec[i], mes_vec[i+1], round_keys);
        enc_vec.push_back(mes_vec[i]);
        enc_vec.push_back(mes_vec[i+1]);
    }
}

void decryption(vector<uint64_t>& mes_vec, vector<uint64_t>& key_vec, vector<uint64_t>& enc_vec) {
    int size = mes_vec.size();
    vector<uint64_t> round_keys;
    for (int i = 0; i < size; i+=2) {
        round_keys = keygen(key_vec[i], key_vec[i+1]);
        speck_decrypt_block(mes_vec[i], mes_vec[i+1], round_keys);
        cbc(mes_vec[i], mes_vec[i+1], enc_vec[i], enc_vec[i+1]);
    }
}

string mdc2(string message) {
    uint64_t c1 = 0x52525252525252525252525252525252;
    uint64_t c2 = 0x25252525252525252525252525252525;


    uint64_t rand_k1 = 0x6A09E667F3BCC908;
    uint64_t rand_k2 = 0xBB67AE8584CAA73B;
    uint64_t h1 = c1, h2 = c2;

    for (size_t i = 0; i < message.size(); i += 16) {
        uint64_t block1 = 0, block2 = 0;
        size_t len = min<size_t>(16, message.size() - i);
        
        for (size_t j = 0; j < len; ++j) {
            if (j < 8) block1 |= (uint64_t)message[i + j] << (8 * j);
            else       block2 |= (uint64_t)message[i + j] << (8 * (j - 8));
        }

        vector<uint64_t> keys1 = keygen(rand_k1, rand_k2);
        vector<uint64_t> keys2 = keygen(rand_k2, rand_k1);

        uint64_t c1_left = block1, c1_right = block2;
        speck_encrypt_block(c1_left, c1_right, keys1);

        uint64_t c2_left = block1, c2_right = block2;
        speck_encrypt_block(c2_left, c2_right, keys2);

        h1 ^= c1_left ^ c2_left;
        h2 ^= c1_right ^ c2_right;
        

    }
    stringstream ss;
    ss << hex << setfill('0') 
       << setw(16) << h1 << setw(16) << h2
       << setw(16) << h1 << setw(16) << h2; // Для 256 бит
    return ss.str();

}



int main() {
    string message = "ya blin ochen lublyu belyashi";
    string key = "i shaurmu ya tozhe ochen lublyu";
    vector<uint64_t> key_vec;
    vector<uint64_t> mes_vec;
    vector<uint64_t> enc_vec;
    uint64_t init_vector_l = crypt_random();
    uint64_t init_vector_r = crypt_random();
    enc_vec.push_back(init_vector_l);
    enc_vec.push_back(init_vector_r);

    str_to_bin(key, key_vec, message, mes_vec);
    if(mes_vec.size()%2 != 0) mes_vec.push_back(0);
    if(key_vec.size()%2 != 0) key_vec.push_back(0);
    cout << "Start message blocks:" << endl;
    for (int i = 0; i < mes_vec.size(); i++) {
        cout << "Block " << i+1 << ": " << mes_vec[i] << endl;
    }
    cout << "Encrypted blocks:" << endl;
    encryption(mes_vec, key_vec, enc_vec);
    for (int i = 0; i < mes_vec.size(); i++) {
        cout << "Block " << i+1 << ": " << enc_vec[i] << endl;
    }
    cout << "Decrypted blocks:" << endl;
    decryption(mes_vec, key_vec, enc_vec);
    for (int i = 0; i < mes_vec.size(); i++) {
        cout << "Block " << i+1 << ": " << mes_vec[i] << endl;
    }
    
    cout << blocks_to_str(mes_vec) << endl;

    cout << mdc2(message) << " " << mdc2(blocks_to_str(mes_vec)) << endl;
    return 0;
}