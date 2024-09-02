#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include<sys/types.h> //! Types Aliass
#include<net/ethernet.h>
#include<unistd.h>
#include<net/if.h>
#include<net/if_media.h>
#include<string.h>
#include<errno.h>
#include<stdbool.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <assert.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <openssl/hmac.h>
#include <sys/reboot.h>
#include <strings.h>
#include <yaml.h>
#include <openssl/sha.h>
#include <time.h>
#include <libusb.h>
#include <ctype.h>
//! sysctl
#include <sys/types.h>
#include <sys/sysctl.h>
#include <inttypes.h>


#define CRC64_POLY 0x42F0E1EBA9EA3693ULL
#define CRC64_INIT 0xFFFFFFFFFFFFFFFFULL
#define HTTP_MAX_RESPONSE_SIZE 1024
#define MAX_INTERFACES 30
#define GNID_ACCESS_TOKEN_FILEPATH "/var/db/tid.db"
#define GNID_REGISTER_ID_FILEPATH "/var/db/id.db"
#define GNID_REGISTER_EXPIRE_FILEPATH "/var/db/eid.db"
//#define DEBUG_GENID


char* REGID_FILEPATH = NULL;
char* TOKID_FILEPATH = NULL;


typedef struct {
    char** data;
    uint32_t size;
    uint32_t capacity;
}Layer2Vector_t;
int Layer2Vector_Init(Layer2Vector_t* _vector,uint32_t _capacity){
    if(_vector == NULL || _capacity == 0) return -1;
    _vector->capacity = _capacity;
    _vector->size = 0;
    _vector->data = (char**)malloc(sizeof(char*));
    if(_vector->data) return 0;
    return -1;
}
int Layer2Vector_insert(Layer2Vector_t* _vector,const char* _data, uint16_t _datalen){
    if(_vector == NULL || _vector->size == _vector->capacity || _data == NULL || _datalen == 0) return -1;
    _vector->data[_vector->size] = (char*)malloc(_datalen+1);
    if(_vector->data[_vector->size]){
        sprintf(_vector->data[_vector->size],"%s",_data);
        _vector->size++;
        return 0;
    }
    return -1;
}
char* Layer2Vector_remove(Layer2Vector_t* _vector){
    if(_vector == NULL || _vector->size == 0) return NULL;
    char* tmp = strdup(_vector->data[_vector->size-1]);
    free(_vector->data[_vector->size-1]);
    _vector->size--;
    return tmp;
}
void Layer2Vector_PrintAll(Layer2Vector_t* _vector){
    if(_vector){
        for(int i = 0; i < _vector->size; i++){
            fprintf(stdout,"%s\n",_vector->data[i]);
        }   
    }
}
int Layer2Vector_DeInit(Layer2Vector_t* _vector){
    if(_vector == NULL) return 0;
    //! Free Size
    for(int i = 0; i < _vector->size; ++i){
        if(_vector->data[i]) free(_vector->data[i]);
    }
    //! Free Capacity
    free(_vector->data);
    return 0;
}
size_t GenID_WriteCallback(void *contents, size_t size, size_t nmemb, void *odata){
	size_t total_size = size * nmemb;
	char* ptrodata = (char*)odata;
	if(total_size < HTTP_MAX_RESPONSE_SIZE){
	    strncpy(odata,contents,total_size);
		ptrodata[total_size] = '\0';
	}else{
		total_size = 1;
        memcpy(odata,0x00,1);
	}
	return total_size;
}
int GenID_ReadUUID(char*);
int GenID_CalcCRC64(const uint8_t*, const size_t, uint64_t*);
int GenID_GetAllEthernetAddresses(Layer2Vector_t*);
int GenID_ApplyObfuscation(const Layer2Vector_t*,Layer2Vector_t*,const uint8_t*, const size_t,uint64_t*);
int GenID_LoadAccessToken(uint8_t*, size_t*);
int GenID_DumpAccessToken(const char*);
int GenID_LoadRegistrationID(char*, const size_t);
int GenID_DumpRegistrationID(const char*);
int GenID_LoadExpiryRegistrationID(char*, const size_t);
int GenID_DumpExpiryRegistrationID(const char*);
int GenID_Layer2ToJson(const Layer2Vector_t*, char*, const size_t, const uint64_t);
int GenID_DoRegister(const char*, const char*);
int GenID_DoCheckRegister(const char*, const char*);

int main(int argc, char* argv[]){
    int flag = -1;
    if(argc == 2){
        if(strlen(argv[1]) == 1 && strcmp(argv[1],"0") == 0 || strcmp(argv[1],"1") == 0){
            flag = atoi(argv[1]);
        }
    }
    char regid[100];
    if(flag == 0 || flag == 1){
        uint8_t token[32];
        size_t tokenlen = 0;
        if(GenID_LoadAccessToken(token,&tokenlen) != -1){
            #ifdef DEBUG_GENID
            for(int i = 0; i < tokenlen; ++i){
                fprintf(stdout,"%02x",token[i]);
            }
            fprintf(stdout,"\n");
            #endif
            Layer2Vector_t orignal_addrs;
            Layer2Vector_t obfuscated_addrs;
            Layer2Vector_Init(&orignal_addrs, 20);
            Layer2Vector_Init(&obfuscated_addrs, 20);
            uint64_t scrambled = 0;
            if(GenID_GetAllEthernetAddresses(&orignal_addrs) != -1){
                #ifdef DEBUG_GENID
                Layer2Vector_PrintAll(&orignal_addrs);
                #endif
                if(GenID_ApplyObfuscation(&orignal_addrs,&obfuscated_addrs,token, tokenlen, &scrambled) != -1){
                    #ifdef DEBUG_GENID
                    Layer2Vector_PrintAll(&obfuscated_addrs);
                    #endif
                    char layers2json_str[1024];
                    char registration_id[100];
                    if(GenID_Layer2ToJson(&obfuscated_addrs,layers2json_str,sizeof(layers2json_str), scrambled) != -1){
                        #ifdef DEBUG_GENID
                        fprintf(stdout,"%s\n",layers2json_str);
                        #endif
                        char token_str[tokenlen*2+1];
                        char* token_str_ptr=token_str;
                        for(int i = 0; i < tokenlen; i++){
                            snprintf(token_str_ptr,3,"%02x",token[i]);
                            token_str_ptr++;
                            token_str_ptr++;
                        }
                        token_str[tokenlen*2] = '\0';
                        if(GenID_LoadRegistrationID(registration_id,sizeof(registration_id)) == -1 || flag == 1){
                            if(GenID_DoRegister(layers2json_str,token_str) != -1){
                                #ifdef DEBUG_GENID
                                fprintf(stdout,"Registration Success...\n");
                                #endif
                                exit(EXIT_SUCCESS);
                            }else{
                                #ifdef DEBUG_GENID
                                fprintf(stdout,"Registration Failed...\n");
                                #endif
                            }
                        }else if(flag==0){
                            if(GenID_DoCheckRegister(layers2json_str,registration_id) != -1){
                                #ifdef DEBUG_GENID
                                fprintf(stdout,"Registration Verfied...\n");
                                #endif
                                exit(EXIT_SUCCESS);
                            }else{
                                #ifdef DEBUG_GENID
                                fprintf(stdout,"Registration Verification Failed...\n");
                                #endif
                            }
                        }
                    }
                }
            }
        }
    }else if(GenID_LoadRegistrationID(regid,100) != -1 && strlen(regid) >= 32){
        fprintf(stdout,"%s\n",regid);
        exit(EXIT_SUCCESS);
    }
    exit(EXIT_FAILURE);
}
int GenID_ReadUUID(char* _uuid){
    if(_uuid){
        int _mib[2];
        char _m_uuid[37];
        size_t _uuid_size = sizeof(_m_uuid);
        _mib[0] = CTL_KERN;
        _mib[1] = KERN_HOSTUUID;
        if(sysctl(_mib, 2, _m_uuid, &_uuid_size, NULL, 0) != -1){
            _m_uuid[_uuid_size] = '\0';
            strcpy(_uuid, _m_uuid);
            return 0;
        }
    }
    return -1;
}
int GenID_CalcCRC64(const uint8_t* _data, const size_t _datalen, uint64_t* _data_crc){
    if(_data && _datalen && _data_crc){
        static uint64_t table[256];
        uint64_t crc = CRC64_INIT;
        int length = _datalen;
        // Generate the CRC table
        for (uint64_t i = 0; i < 256; i++) {
            uint64_t crc_table = i;
            for (uint64_t j = 8; j > 0; j--) {
                if (crc_table & 1) {
                    crc_table = (crc_table >> 1) ^ CRC64_POLY;
                } else {
                    crc_table >>= 1;
                }
            }
            table[i] = crc_table;
        }   
        // Calculate CRC
        while (length--) {
            uint8_t index = (crc ^ *_data++) & 0xFF;
            crc = (crc >> 8) ^ table[index];
        }
        *_data_crc = crc ^ CRC64_INIT;
        return 0;
        
    }
    return -1;
}
int GenID_GetAllEthernetAddresses(Layer2Vector_t* _addrs){
    if(_addrs){
        struct ifaddrs* interfaces;
        struct ifaddrs* next_interface;
    	struct ifmediareq ifmr;
    	unsigned char* next_phy_addr;
    	if(getifaddrs(&interfaces) == 0){
    		next_interface = interfaces;
    		int fd = socket(AF_UNIX,SOCK_DGRAM,0);
    		while(next_interface != NULL && fd > -1){
    			if(next_interface->ifa_addr->sa_family == AF_LINK){
    				//! read physical addr
    				next_phy_addr = (unsigned char*)LLADDR((struct sockaddr_dl*)next_interface->ifa_addr);
    				//! validate address
    				if(!next_phy_addr[0] && !next_phy_addr[1] && !next_phy_addr[2] &&
    				   !next_phy_addr[3] && !next_phy_addr[4] && !next_phy_addr[5]){
    					   next_interface = next_interface->ifa_next;
    					   continue;
    				}
    				//! read media type
    				memset(&ifmr,0, sizeof(ifmr));
    				strcpy(ifmr.ifm_name,next_interface->ifa_name);
    				if(ioctl(fd,SIOCGIFMEDIA,(caddr_t)&ifmr) > -1)
    					if(IFM_TYPE(ifmr.ifm_active) == IFM_ETHER){
    						char data[50];
    						snprintf(data,50,"%02x:%02x:%02x:%02x:%02x:%02x",next_phy_addr[0],next_phy_addr[1],next_phy_addr[2],next_phy_addr[3],next_phy_addr[4],next_phy_addr[5]);
                            Layer2Vector_insert(_addrs,data,strlen(data));
                        }
    			}
    			next_interface = next_interface->ifa_next;
    		}
    		freeifaddrs(interfaces);
    		close(fd);
    		return 0;
    	}
    }
	return -1;
}
int GenID_ApplyObfuscation(const Layer2Vector_t* _orignal_addrs, Layer2Vector_t* _obfuscated_addrs, const uint8_t* _token, const size_t _tokenlen, uint64_t* _scrambled){
    char _local_uuid[40];
    if(_orignal_addrs && _obfuscated_addrs && _token && _tokenlen > 0 && _scrambled && GenID_ReadUUID(_local_uuid) != -1){
        uint64_t _local_uuid_crc = 0;
        uint64_t _local_token_crc = 0;
        uint64_t _local_scrambled_crc = 0;
        if(GenID_CalcCRC64(_token,_tokenlen,&_local_token_crc) != -1 && GenID_CalcCRC64((uint8_t*)_local_uuid,strlen(_local_uuid),&_local_uuid_crc) != -1){
            #ifdef DEBUG_GENID
            fprintf(stdout,"UUID: %lu\n",_local_uuid_crc);
            #endif
            _local_scrambled_crc = _local_token_crc ^ _local_uuid_crc;
            srand(_local_scrambled_crc);
            int mask_0 = rand();
            int mask_1 = rand();
            int mask_2 = rand();
            int mask_3 = rand();
            int mask_4 = rand();
            int mask_5 = rand();
            struct ether_addr _local_addr;
            char _local_addr_str[50];
            uint8_t xor_layers[ETHER_ADDR_LEN];
            for(int i = 0; i < _orignal_addrs->size; ++i){
                if(ether_aton_r(_orignal_addrs->data[i],&_local_addr) != NULL){
                    xor_layers[0] = _local_addr.octet[5] ^ mask_0;
                    xor_layers[1] = _local_addr.octet[3] ^ mask_2;
                    xor_layers[2] = _local_addr.octet[1] ^ mask_4;
                    xor_layers[3] = _local_addr.octet[4] ^ mask_1;
                    xor_layers[4] = _local_addr.octet[2] ^ mask_3;
                    xor_layers[5] = _local_addr.octet[0] ^ mask_5;
                    snprintf(_local_addr_str,50,"%02x:%02x:%02x:%02x:%02x:%02x",xor_layers[0],xor_layers[1],xor_layers[2],xor_layers[3],xor_layers[4],xor_layers[5]);
                    Layer2Vector_insert(_obfuscated_addrs,_local_addr_str,strlen(_local_addr_str));
                }
            }
            *_scrambled = _local_scrambled_crc;
            return 0;
            
        }
    }
    return -1;
    
}

int GenID_LoadAccessToken(uint8_t* _otoken, size_t* _otokenlen){
    if(_otoken && _otokenlen){
        FILE* access_token_reader = fopen(GNID_ACCESS_TOKEN_FILEPATH,"rb");
        if(access_token_reader){
            *_otokenlen = 0;
            while(fscanf(access_token_reader,"%02x",&_otoken[*_otokenlen]) != EOF && (*_otokenlen)++ < 32);
            fclose(access_token_reader);
            return 0;
        }
    }
    return -1;
}
int GenID_DumpAccessToken(const char*  _itoken){
    if(_itoken){
        FILE* access_token_writer = fopen(GNID_ACCESS_TOKEN_FILEPATH,"wb");
        if(access_token_writer){
            fprintf(access_token_writer,"%s",_itoken);
            fclose(access_token_writer);
            return 0;
        }
    }
    return -1;   
}
int GenID_LoadRegistrationID(char* _regid, const size_t _regidlen){
    if(_regid && _regidlen){
        FILE* regid_reader = fopen(GNID_REGISTER_ID_FILEPATH,"rb");
        if(regid_reader){
            fgets(_regid,_regidlen,regid_reader);
            fclose(regid_reader);
            if(strlen(_regid) > 0) return 0;
        }
    }
    return -1;
}
int GenID_DumpRegistrationID(const char*  _regid){
    if(_regid){
        FILE* regid_writer = fopen(GNID_REGISTER_ID_FILEPATH,"wb");
        if(regid_writer){
            fprintf(regid_writer,"%s",_regid);
            fclose(regid_writer);
            return 0;
        }
    }
    return -1;   
}
int GenID_LoadExpiryRegistrationID(char* _regid, const size_t _regidlen){
    if(_regid && _regidlen){
        FILE* regid_reader = fopen(GNID_REGISTER_EXPIRE_FILEPATH,"rb");
        if(regid_reader){
            fgets(_regid,_regidlen,regid_reader);
            fclose(regid_reader);
            if(strlen(_regid) > 0) return 0;
        }
    }
    return -1;
}
int GenID_DumpExpiryRegistrationID(const char*  _regid){
    if(_regid){
        FILE* regid_writer = fopen(GNID_REGISTER_EXPIRE_FILEPATH,"wb");
        if(regid_writer){
            fprintf(regid_writer,"%s",_regid);
            fclose(regid_writer);
            return 0;
        }
    }
    return -1;   
}

int GenID_Layer2ToJson(const Layer2Vector_t* _layers2, char* _layers2json, const size_t _layers2json_max, const uint64_t _scrambled){
    if(_layers2 && _layers2json && _scrambled ){
        struct json_object *root = json_object_new_object();
        struct json_object *root_array = json_object_new_array();
        if(root && root_array){
            for (int i = 0; i < _layers2->size; i++) {
                json_object *root_array_item = json_object_new_string(_layers2->data[i]);
                if(root_array_item)
                    json_object_array_add(root_array, root_array_item);
            }
            char scrambled_eggs_str[21];
            snprintf(scrambled_eggs_str,21,"%" PRIu64,_scrambled);
            json_object *scrambled_eggs = json_object_new_string(scrambled_eggs_str);
            json_object_object_add(root, "interfaces", root_array);
            json_object_object_add(root, "scrambled_eggs", scrambled_eggs);
            snprintf(_layers2json,_layers2json_max,"%s",json_object_to_json_string(root));
            json_object_put(root);
            return 0;
        }
    }
    return -1;
}
int GenID_DoRegister(const char* _layers2json,const char* _access_token){
    int retcode = -1;
    if(_layers2json && _access_token){
        CURL *curl_handle;
        CURLcode curl_err;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_handle = curl_easy_init();
        long HTTPcode = 404;
        char HTTPData[HTTP_MAX_RESPONSE_SIZE];
        char HTTPEndpoint[200];
        snprintf(HTTPEndpoint,200,"https://firewall.thingzeye.com/thingzeye_enterprise/%s/ot_registration",_access_token);
        #ifdef DEBUG_GENID
        fprintf(stdout,"%s\n",HTTPEndpoint);
        #endif
	    if(curl_handle){    
			curl_easy_setopt(curl_handle, CURLOPT_URL, HTTPEndpoint);
			curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS,_layers2json);
			struct curl_slist *curl_header_options = NULL;
			curl_header_options = curl_slist_append(curl_header_options, "Content-Type: application/json");
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, curl_header_options);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, GenID_WriteCallback);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, HTTPData);
			curl_err = curl_easy_perform(curl_handle);
			curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &HTTPcode);
			if(curl_err == CURLE_OK && HTTPcode == 200){
				retcode = 0;
                #ifdef DEBUG_GENID
                fprintf(stdout,"Registratioin Status: %s\n",HTTPData);
                #endif
                struct json_object *root = json_tokener_parse(HTTPData);
                struct json_object *key = NULL;
                if(root){
                    //! Registration Key
                    if (json_object_object_get_ex(root, "key", &key)){
                        char _key[100];
                        snprintf(_key,100,"%s",json_object_get_string(key));
                        if(GenID_DumpRegistrationID(_key)){
                            #ifdef DEBUG_GENID
                            fprintf(stdout,"Successfully Registered Firewall.\n");
                            #endif
                        }
                    }
                    //! Registration Expiry
                    if (json_object_object_get_ex(root, "expired_on", &key)){
                        char _key[100];
                        snprintf(_key,100,"%d",json_object_get_int(key));
                        if(GenID_DumpExpiryRegistrationID(_key)){
                            #ifdef DEBUG_GENID
                            fprintf(stdout,"Successfully Registered Firewall.\n");
                            #endif
                        }
                    }
                    //! Next Access Token
                    if (json_object_object_get_ex(root, "next_key", &key)){
                        char _key[100];
                        snprintf(_key,100,"%s",json_object_get_string(key));
                        if(GenID_DumpAccessToken(_key)){
                            #ifdef DEBUG_GENID
                            fprintf(stdout,"Successfully Registered Firewall.\n");
                            #endif
                        }
                    }
                    json_object_put(root);
                }
			}else{
                fprintf(stdout,"Error While Registring Firewall: %s\n",HTTPData);
            }
		}
		curl_easy_cleanup(curl_handle);
	}
	curl_global_cleanup();
    return retcode;
}

int GenID_DoCheckRegister(const char* _layers2json,const char* _reg_id){
    int retcode = -1;
    if(_layers2json && _reg_id){
        CURL *curl_handle;
        CURLcode curl_err;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_handle = curl_easy_init();
        long HTTPcode = 404;
        char HTTPData[HTTP_MAX_RESPONSE_SIZE];
        char HTTPEndpoint[200];
        snprintf(HTTPEndpoint,200,"https://firewall.thingzeye.com/thingzeye_enterprise/%s/ot_verification",_reg_id);
        #ifdef DEBUG_GENID
        fprintf(stdout,"%s\n",HTTPEndpoint);
        #endif
	    if(curl_handle){    
			curl_easy_setopt(curl_handle, CURLOPT_URL, HTTPEndpoint);
			curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS,_layers2json);
			struct curl_slist *curl_header_options = NULL;
			curl_header_options = curl_slist_append(curl_header_options, "Content-Type: application/json");
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, curl_header_options);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, GenID_WriteCallback);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, HTTPData);
			curl_err = curl_easy_perform(curl_handle);
			curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &HTTPcode);
			if(curl_err == CURLE_OK && HTTPcode == 200){
                printf("%s\n",_reg_id);
				retcode = 0;
			}else{
                fprintf(stdout,"Error While Firewall Registration Verification: %s\n",HTTPData);
            }
		}
		curl_easy_cleanup(curl_handle);
	}
	curl_global_cleanup();
    return retcode;
}

