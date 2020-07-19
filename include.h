
const char* hashlib_dllname;
void hashlib_init(const char* dllname)
{
	LoadLibraryA(dllname);
	hashlib_dllname = dllname;
}
void* hashlib_getproc(const char* func)
{
	void* hmod = GetModuleHandleA(hashlib_dllname);
	void* addr = (void*)GetProcAddress((HMODULE)hmod, func);
	return addr;
}

//==================== MD2 ====================//

string md2_string(string input)
{
	void* addr = hashlib_getproc("ex_md2_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string md2_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_md2_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string md2_file(string filename)
{
	void* addr = hashlib_getproc("ex_md2_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== MD4 ====================//

string md4_string(string input)
{
	void* addr = hashlib_getproc("ex_md4_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string md4_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_md4_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string md4_file(string filename)
{
	void* addr = hashlib_getproc("ex_md4_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== MD5 ====================//

string md5_string(string input)
{
	void* addr = hashlib_getproc("ex_md5_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string md5_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_md5_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string md5_file(string filename)
{
	void* addr = hashlib_getproc("ex_md5_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA1 ====================//

string sha1_string(string input)
{
	void* addr = hashlib_getproc("ex_sha1_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha1_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha1_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha1_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha1_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA224 ====================//

string sha224_string(string input)
{
	void* addr = hashlib_getproc("ex_sha224_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha224_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha224_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha224_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha224_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA256 ====================//

string sha256_string(string input)
{
	void* addr = hashlib_getproc("ex_sha256_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha256_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha256_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha256_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha256_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA384 ====================//

string sha384_string(string input)
{
	void* addr = hashlib_getproc("ex_sha384_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha384_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha384_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha384_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha384_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA512 ====================//

string sha512_string(string input)
{
	void* addr = hashlib_getproc("ex_sha512_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha512_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha512_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha512_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha512_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA3_224 ====================//

string sha3_224_string(string input)
{
	void* addr = hashlib_getproc("ex_sha3_224_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha3_224_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha3_224_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha3_224_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha3_224_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA256 ====================//

string sha3_256_string(string input)
{
	void* addr = hashlib_getproc("ex_sha3_256_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha3_256_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha3_256_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha3_256_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha3_256_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA384 ====================//

string sha3_384_string(string input)
{
	void* addr = hashlib_getproc("ex_sha3_384_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha3_384_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha3_384_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha3_384_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha3_384_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}

//==================== SHA512 ====================//

string sha3_512_string(string input)
{
	void* addr = hashlib_getproc("ex_sha3_512_string");
	char* hash = ((char*(__stdcall*)(const char*))addr)(input.c_str());
	return string(hash);
}
string sha3_512_buffer(void* buff, size_t len)
{
	void* addr = hashlib_getproc("ex_sha3_512_buffer");
	char* hash = ((char*(__stdcall*)(void*, size_t))addr)(buff, len);
	return string(hash);
}
string sha3_512_file(string filename)
{
	void* addr = hashlib_getproc("ex_sha3_512_file");
	char* hash = ((char*(__stdcall*)(const char*))addr)(filename.c_str());
	return string(hash);
}
