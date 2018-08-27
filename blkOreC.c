#include "fastore/crypto.h"
#include "fastore/ore_blk.h"
#include "fastore/errors.h"
#include "fastore/OREOrderScheme.h"
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int _error;
#define ERR_CHECK(x) if((err = x) != ERROR_NONE) { printf ("\nError!"); }
#define CEIL(x, y) (((x) + (y) - 1) / (y))
int ore_custom_setup (ore_blk_secret_key sk, ore_blk_params params, byte usr_keybuf1[], byte usr_keybuf2[]){

  int err;
  AES_128_Key_Expansion(usr_keybuf1, &sk->prf_key);
  AES_128_Key_Expansion(usr_keybuf2, &sk->prp_key);

  
  memcpy(sk->params, params, sizeof(ore_blk_params));
  sk->initialized = true;

  return ERROR_NONE;
}

void stringhextobytes(unsigned char *val, const char hexstring[], int size){
  const char *pos = hexstring;

  for (int i = 0; i < size; i++){
    sscanf(pos, "%02hhX", &val[i]);
    pos += 2 * sizeof(char);
  }
 
}
JNIEXPORT void JNICALL Java_depspace_confidentiality_OREOrderScheme_blkOreC
//JNIEXPORT void JNICALL Java_OREOrderScheme_blkOreC
//JNIEXPORT void JNICALL Java_blkOreJNI_blkOreC
  (JNIEnv *env, jobject obj, jobjectArray args, jint op_arg){
  
  //recebendo argumentos
  int n_args = (*env)->GetArrayLength(env, args);

  const char *argC[n_args];
  
  for (int i = 0; i < n_args; i++){
    jstring string = (jstring) ((*env)->GetObjectArrayElement(env, args, i));
    argC[i] = (*env)->GetStringUTFChars(env, string, 0);
  }

  //Inicializando parametros
  int nbits = 32;
  int out_blk_len = 8;
  
  int err, ret, res;
  
  ore_blk_params params;
  ERR_CHECK(init_ore_blk_params(params, nbits, out_blk_len));
  //printf("Parametros:\nInit:%d\nnbits: %d\nblk_len:%d\n",
	//params->initialized, params->nbits, params->block_len);

  //Selecionando opcao
  int op = (int) op_arg;
  uint32_t len_left_block  = 20;
  uint32_t len_right_block = 32;
  uint32_t len_nonce = sizeof(block);
  uint32_t nblocks = CEIL(params->nbits, params->block_len);
  uint32_t len_comp_left = nblocks * len_left_block;
  uint32_t len_comp_right = len_nonce + nblocks * len_right_block;

  switch (op){
  	case (1):{
		//printf("encrypt\n");

  		ore_blk_secret_key sk;
  		unsigned char *byte_key;
  		byte_key = (unsigned char*) argC[1];
  		uint32_t key_size = strlen(argC[1]);
 
  		byte * usr_keybuf;
  		usr_keybuf = malloc (SHA256_OUTPUT_BYTES*sizeof(byte));
  		ERR_CHECK(sha_256((byte *)usr_keybuf, SHA256_OUTPUT_BYTES, byte_key, key_size));
 
  		byte prf_key[16]; 
  		memcpy(prf_key, usr_keybuf, 16 * sizeof(byte));
  		byte prp_key[16]; 
  		memcpy(prp_key, usr_keybuf + 16, 16 * sizeof(byte));
 
  		ERR_CHECK(ore_custom_setup(sk, params, prf_key, prp_key));
  
		uint64_t n1 = (uint64_t) (atoi(argC[2]));
  		ore_blk_ciphertext ctxt1;
  		ERR_CHECK(init_ore_blk_ciphertext(ctxt1, params));
  		ERR_CHECK(ore_blk_encrypt_ui(ctxt1, sk, n1));

		/* Teste
		 *
		printf("\nCTXT: ");
		for (int i=0; i < len_comp_left; i++)
			printf("%02hhX ", ctxt1->comp_left[i]);
		for (int i=0; i < len_comp_right; i++)
			printf("%02hhX ", ctxt1->comp_right[i]);*/

		//Preparando dados para retorno
		jclass thisClass = (*env)->GetObjectClass(env, obj);
		jfieldID fidCtxt = (*env)->GetFieldID(env, thisClass, "ciphertext", "[B");
		if (NULL == fidCtxt) printf("\nciphertext Field ID error");
		jbyteArray ctxt_ret = (*env)->NewByteArray(env, len_comp_left + len_comp_right);
		(*env)->SetByteArrayRegion(env, ctxt_ret, 0, len_comp_left, (const jbyte *)ctxt1->comp_left);
		(*env)->SetByteArrayRegion(env, ctxt_ret, len_comp_left, len_comp_right, (const jbyte *)ctxt1->comp_right);
		(*env)->SetObjectField(env, obj, fidCtxt, ctxt_ret);
		//ERR_CHECK(clear_ore_blk_ciphertext(ctxt1));

		break;}
	case (2):{
		//printf("compare\n");

		unsigned char *ctxt1_bytes;
		ctxt1_bytes = malloc(len_comp_left + len_comp_right);
	        stringhextobytes(ctxt1_bytes, argC[1], len_comp_left + len_comp_right);
		/* Teste
		 *
		printf("\nCTXT1: ");
		for (int i=0; i < len_comp_left + len_comp_right; i++)
			printf("%02hhX ", ctxt1_bytes[i]);*/
		
		unsigned char *ctxt2_bytes;
		ctxt2_bytes = malloc(len_comp_left + len_comp_right);
	        stringhextobytes(ctxt2_bytes, argC[2], len_comp_left + len_comp_right);
		/*
		 *
		printf("\nCTXT2: ");
		for (int i=0; i < len_comp_left + len_comp_right; i++)
			printf("%02hhX ", ctxt2_bytes[i]);*/

		ore_blk_ciphertext ctxt1;
		ERR_CHECK(init_ore_blk_ciphertext(ctxt1, params));
		
		ore_blk_ciphertext ctxt2;
		ERR_CHECK(init_ore_blk_ciphertext(ctxt2, params));
		
		if (!ctxt1->initialized || !ctxt2->initialized) {
			printf("ERROR_CTXT_NOT_INITIALIZED");
		}

  		memcpy(ctxt1->comp_left, ctxt1_bytes, len_comp_left);
  		memcpy(ctxt1->comp_right, ctxt1_bytes + len_comp_left, len_comp_right);
  		memcpy(ctxt2->comp_left, ctxt2_bytes, len_comp_left);
  		memcpy(ctxt2->comp_right, ctxt2_bytes + len_comp_left, len_comp_right);

		ore_blk_compare (&res, ctxt1, ctxt2);
		//printf("\nRES: %d\n", res);
		
		jclass thisClass = (*env)->GetObjectClass(env, obj);
		jfieldID fidRes = (*env)->GetFieldID(env, thisClass, "res", "I");
		(*env)->SetIntField(env, obj, fidRes, res);

		free(ctxt1_bytes);
		free(ctxt2_bytes);
		break;}
	default:
		printf("Use enc | cmp\n");
  }
}
