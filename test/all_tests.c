#include "smolcert.h"
#include "unity.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

const uint8_t expected_cert_bytes_without_extension[] = {
        0x88, 0x01, 0x01, 0x67, 0x63, 0x6f, 0x6e, 0x6e, 0x63, 0x74, 0x64, 0x82,
  0x1a, 0x62, 0x5e, 0x17, 0x3a, 0x1a, 0x62, 0x5f, 0x68, 0xba, 0x67, 0x63,
  0x6f, 0x6e, 0x6e, 0x63, 0x74, 0x64, 0x58, 0x20, 0x5c, 0x31, 0x03, 0x6e,
  0x49, 0xe9, 0x43, 0x3e, 0x2d, 0xd5, 0xe3, 0xa5, 0xd2, 0x2b, 0xa6, 0x18,
  0xbd, 0x71, 0x58, 0xa1, 0x5f, 0x46, 0x5f, 0x5b, 0xab, 0xb9, 0x66, 0x90,
  0x39, 0x9e, 0x05, 0x8f, 0x81, 0x83, 0x10, 0xf5, 0x41, 0x03, 0x58, 0x40,
  0x54, 0x75, 0x2f, 0x8a, 0x4f, 0x8b, 0x0e, 0x49, 0xac, 0x96, 0xa8, 0x26,
  0x93, 0x30, 0xfb, 0xd8, 0x69, 0xd2, 0x98, 0xf2, 0x23, 0x4b, 0xba, 0x5b,
  0xe3, 0x25, 0x77, 0xc5, 0xd1, 0xbf, 0xba, 0x17, 0xdc, 0xf1, 0x30, 0x08,
  0x59, 0xa7, 0x52, 0x36, 0xae, 0xac, 0xbb, 0x15, 0xf7, 0x35, 0x2f, 0xb2,
  0x90, 0xe9, 0xf7, 0x4a, 0x27, 0xa2, 0xe9, 0x0e, 0x5f, 0x5f, 0x73, 0x53,
  0x90, 0xf3, 0x6a, 0x06};

void test_Parsing_valid_smolcert(void);
void test_ValidateCertificateSignature(void);
void test_parseCertFromfile(void);
void test_convertEd25519PKtoCurve25519(void);

void printKey(uint8_t* key, uint8_t keyLen);

void test_Parsing_valid_smolcert(void) {
  smolcert_t* cert = (smolcert_t*)malloc(sizeof(smolcert_t));

  sc_error_t sc_err = sc_parse_certificate((const uint8_t *)&expected_cert_bytes_without_extension, 
    sizeof(expected_cert_bytes_without_extension), cert);
  TEST_ASSERT_EQUAL(Sc_No_Error, sc_err);

  TEST_ASSERT_EQUAL_UINT64(1, cert->serial_number);
  TEST_ASSERT_EQUAL_STRING("connctd", cert->issuer);
  TEST_ASSERT_EQUAL_STRING("connctd", cert->subject);
  TEST_ASSERT_EQUAL_UINT64(1650419898, cert->validity.not_after);
  TEST_ASSERT_EQUAL_UINT64(1650333498, cert->validity.not_before);
  const uint8_t expected_pub_key[32] = {0x5c, 0x31, 0x03, 0x6e,
  0x49, 0xe9, 0x43, 0x3e, 0x2d, 0xd5, 0xe3, 0xa5, 0xd2, 0x2b, 0xa6, 0x18,
  0xbd, 0x71, 0x58, 0xa1, 0x5f, 0x46, 0x5f, 0x5b, 0xab, 0xb9, 0x66, 0x90,
  0x39, 0x9e, 0x05, 0x8f};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_pub_key, cert->public_key, 32);

  sc_free_cert(cert);
}


void test_ValidateCertificateSignature(void) {
  smolcert_t* cert = (smolcert_t*)malloc(sizeof(smolcert_t));

  sc_error_t sc_err = sc_parse_certificate((const uint8_t *)&expected_cert_bytes_without_extension,
    sizeof(expected_cert_bytes_without_extension), cert);
  TEST_ASSERT_EQUAL(Sc_No_Error, sc_err);

  // We can't use the const array expected_cert_bytes here, since sc_validate_certificate_signature needs
  // to temporarely modify the array. So we copy it to a new location
  uint8_t* cert_bytes = (uint8_t*)malloc(sizeof(expected_cert_bytes_without_extension));
  memcpy(cert_bytes, expected_cert_bytes_without_extension, sizeof(expected_cert_bytes_without_extension));
  sc_err = sc_validate_certificate_signature(cert_bytes, sizeof(expected_cert_bytes_without_extension), cert->public_key);
  TEST_ASSERT_EQUAL(Sc_No_Error, sc_err);

  // Ensure that the validate_signature method did not alter the original buffer
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_cert_bytes_without_extension, cert_bytes, sizeof(expected_cert_bytes_without_extension));

  free(cert_bytes);
  sc_free_cert(cert);
}


uint8_t pubkey[] = {104,176,187,27,171,219,74,12,219,58,6,27,176,48,137,249,166,209,108,47,52,35,86,170,137,245,244,202,146,214,2,111};
void test_parseCertFromfile(void){
  smolcert_t* cert = (smolcert_t*)malloc(sizeof(smolcert_t));
  FILE *fp;
  u_int8_t* buf;
  size_t bufSize;
  
  sc_error_t sc_err;

  fp = fopen("smol.cert","rb");

  if(fp == NULL){
    TEST_ABORT();
  }

  fseek(fp,0,SEEK_END);
  bufSize = ftell(fp);
  rewind(fp);

  buf = (u_int8_t*)malloc(bufSize);
  fread(buf,1,bufSize,fp);
 #ifdef FALSE 
  u_int8_t* ioBuf = buf;
  uint16_t i = 0;

  while(i < bufSize){
    if(i%16 == 0) printf("\n");
    //printf("0x%02x ",*(ioBuf++));
    printf("%d ",(uint8_t)*(ioBuf++));
    //printf("%c ",(char)*(ioBuf++));
    i++;
  }
  #endif
  
  sc_err = sc_parse_certificate(buf,bufSize, cert);
  printf("Issuer: %s\n",cert->issuer);
  printf("Subject: %s\n",cert->subject);

  TEST_ASSERT_EQUAL(Sc_No_Error, sc_err);
  //TEST_ASSERT_EQUAL_UINT8_ARRAY(pubkey, cert->public_key, 32);


  free(buf);
  fclose(fp);
  sc_free_cert(cert);
}

void test_convertEd25519PKtoCurve25519(void){
  smolcert_t* cert = (smolcert_t*)malloc(sizeof(smolcert_t));
  FILE *fp;
  uint8_t* buf;
  size_t bufSize;
  char testCert[] = "smol.cert"; 
  
  sc_error_t sc_err;
  fp = fopen(testCert,"rb");

  if(fp == NULL){
    TEST_ABORT();
  }

  fseek(fp,0,SEEK_END);
  bufSize = ftell(fp);
  rewind(fp);

  buf = (u_int8_t*)malloc(bufSize);
  fread(buf,1,bufSize,fp);
  sc_err = sc_parse_certificate(buf,bufSize, cert);
  TEST_ASSERT_EQUAL_MESSAGE(Sc_No_Error, sc_err,"Error parsing the testcert");
  
  uint8_t edPubkey[32];

  sc_err = sc_get_curve_public_key(cert,edPubkey);
  TEST_ASSERT_EQUAL_MESSAGE(Sc_No_Error, sc_err,"Error getting curve from testcert");
  printKey(edPubkey,32);
  printKey(cert->public_key,32);

  //TODO: validate converted public keys against testVector
  // TEST_ASSERT_EQUAL_ARRAY(edPubKey,edTestVector,"Converted pubKey does not match testvector");

  free(buf);
  fclose(fp);
  sc_free_cert(cert);
}


void printKey(uint8_t* key,uint8_t keyLen){
  for(uint8_t i = 0; i < keyLen; i++)
  {
    if(i%16 == 0) printf("\n");
    printf("%02x ",key[i]);
    
  }

  printf("\n");
  return;
}


int main(void) {
    if (sodium_init() == -1) {
      return 1;
    }
    UNITY_BEGIN();
    RUN_TEST(test_Parsing_valid_smolcert);
    RUN_TEST(test_ValidateCertificateSignature);
    RUN_TEST(test_parseCertFromfile);
    RUN_TEST(test_convertEd25519PKtoCurve25519);
    return UNITY_END();
}