/*
 * Copyright (c) 2017, Cavium, Inc. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Cavium, Inc. nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY CAVIUM INC. ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CAVIUM, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

typedef char *CHAR_PTR;

// Windows 32 Directives

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#include <windows.h>
#include <winbase.h>
#include<windirent.h>

// UNIX Directives
#else
#include <termios.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <dlfcn.h>
#endif

// Standard "C" Directives
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <math.h>

#include <inttypes.h>
#include <openssl/ssl.h>

#include "cavium_defines.h"
#include "cavium_mgmt.h"
#include "cavium_mgmt_cli.h"
#include "cavium_structs.h"
#include "cavium_crypto.h"
#include "cavium_attributes.h"
#include "cavium_wrappers.h"
#include "openssl_util.h"

#include "openssl/crypto.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "openssl/ec.h"
#include "openssl/aes.h"
#include "openssl/des.h"

#ifdef BACKUP_WITH_SMARTCARD
#include "eTPkcs11.h"
#include "pkcs11t.h"
#endif
#include "Cfm2Helper.h"

#ifdef LIQUID_SECURITY_CLIENT
#include "cavium_daemon_intf.h"
#endif
#include "cavium_version.h"

#define BUFSIZE MAX_DATA_LENGTH


char *partition_name = NULL;
unsigned int application_id = -1;
unsigned int session_handle = -1;


char fipsState = 0;
char *fips_state[] = { "zeroized",
    "non-FIPS mode with single factor authentication",
    "non-FIPS mode with two factor authentication(unsupported)",
    "FIPS mode with single factor authentication",
    "FIPS mode with two factor authentication"
};
char *kek_methods[] = { "ECDH", "RSA" };
char *cloning_methods[] = { "Not Supported", "ECDH", "RSA" };
char *audit_status_str[] = { "Not Finalized", "Finalized", "Retrieved" };

char *nitrox_config[] = { "Not configured",
    "16 cores",
    "24 cores",
    "32 cores",
    "55/63 cores"
};

char *userType[] = { "Unknown",
    "CU",
    "CO",
    "PCO",
    "HMCO",
    "AU",
    "PRECO"
};

char *services[] = {
    "BACKUP_BY_CU",
    "BACKUP_BY_CO",
    "CLONING",
    "USER_MGMT",
    "MISC_CO",
    "USE_KEY",
	"MANAGE_KEY",
};

// Prototype Declarations
void Help_AllCommands(char *pAppName);  // All Commands Available
int CfmUtil_main(int argc, char **argv);
void HexPrint(Uint8 * data, Uint32 len);
int ReadFileByMap(char *pbFileName,
                  char **ppMemBlock, unsigned int *pulMemSize);
int ReadBinaryFile(char *pbFileName, char **ppMemBlock, unsigned int *pulMemSize);      // Read Binary File for Input
int WriteBinaryFile(char *pbFileName, char *pMemBlock,
                    unsigned long ulMemSize);
int getAttributeValue(Uint32 ulAttribute, Uint8 ** pAttribute,
                      Uint32 * ulAttributeLen);
unsigned int GetConsoleString(char *pPrompt, char *pBuffer,
                              unsigned int nBufferSize);
char **GetCommandLineArgs(char *buff, int *_argc);
int GetPassword(char *pPrompt,
                char *pPrompt2, char *pBuffer, int *pulBufferLen);
Uint32 zeroize(int argc, char **argv);
Uint32 login(int argc, char **argv);

#define VECTOR_SIZE             100
#define MAX_FILENAME_SIZE       256
#define CAV_SIG_IMPORTED_KEY    0xCAFEFEED
#define CAV_SIG_HSM_KEY         0xEEFCFCEA

#define VECTOR_SIZE             100
#define MAX_FILENAME_SIZE       256
#define CAV_SIG_IMPORTED_KEY    0xCAFEFEED
#define CAV_SIG_HSM_KEY         0xEEFCFCEA

INT8 atox(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

char *retString(char *pos)
{
    char *end;
    while (*pos == ' ' || *pos == ':' || *pos == '=')
        pos++;
    for (end = pos; *end != '\n' && *end != ';'; end++)
        continue;
    *end = '\0';
    return pos;
}

#define atox2macro(str, val) \
{ \
    char *point; \
    int i = 0; \
    \
    point = strstr(str, "0x"); \
    if (point != NULL) \
    { \
        point += 2; \
        i   += 2; \
        for(*val = 0; i < strlen(str); i++, point++) \
        *val = (*val << 4) | atox(*point); \
    } else \
    *val = atoi(str);\
}


#define getFieldStr(buf, str, f, size, cnt) \
{ \
    char *pos = NULL; \
    if (strncmp(buf, str, strlen(str)) == 0) \
    pos = strstr(buf, str); \
    if (pos)  \
    { \
        pos   += strlen(str); \
        pos    = retString(pos); \
        if (!n3fips_strncpy(f, pos,size,strlen(pos))) \
        cnt += 1; \
        else { \
            printf("Field %s has incompatible value of size %zu\n", str, strlen(pos));\
        }\
        memset(buf, 0, sizeof(buf));\
        continue;\
    } \
}

#define getField(buf, str, f, type, cnt) \
{ \
    char *pos = NULL; \
    type *val = f; \
    if (strncmp(buf, str, strlen(str)) == 0) \
    pos = strstr(buf, str); \
    if (pos)  \
    { \
        pos   += strlen(str); \
        pos    = retString(pos); \
        atox2macro(pos, val); \
        cnt++;\
        memset(buf, 0, sizeof(buf));\
        continue; \
    } \
}


// a reasonable upper limit to the number of params that get read in.
CHAR_PTR vector[VECTOR_SIZE + 2];

// dynamic buffers that get allocated for params
// a reasonable upper limit to the number of params that get read in.
CHAR_PTR dyn_vector[VECTOR_SIZE + 2];

// number of buffers in the vector
Uint32 ulDynVectorSize = 0;

void initDynamicBufferVector()
{
    for (ulDynVectorSize = 0; ulDynVectorSize < VECTOR_SIZE;
         ulDynVectorSize++)
        dyn_vector[ulDynVectorSize] = 0;

    ulDynVectorSize = 0;
}

void clearAndResetDynamicBufferVector()
{
    Uint32 i = 0;
    for (i = 0; i < VECTOR_SIZE; i++) {
        if (dyn_vector[i] != 0)
            free(dyn_vector[i]);
        dyn_vector[i] = 0;
    }

    ulDynVectorSize = 0;
}

Uint8 *hashSHA256(Uint8 * input, Uint32 size)
{

    EVP_MD_CTX c;
    unsigned char *md;
    unsigned int md_len, ret = 0;

    const EVP_MD *type = NULL;
    type = EVP_get_digestbyname("SHA256");

    md = CALLOC_WITH_CHECK(1, SHA256_SIZE);
    EVP_MD_CTX_init(&c);
    if ((ret = EVP_DigestInit(&c, type)) == 0)
        goto error;
    if ((ret = EVP_DigestUpdate(&c, input, size)) == 0)
        goto error;
    if ((ret = EVP_DigestFinal(&c, md, &md_len)) == 0)
        goto error;
  error:
    if (!ret) {
        free(md);
        md = NULL;
    }
    EVP_MD_CTX_cleanup(&c);
    return md;
}

Uint8 verifySignature(BIO * cbio, Uint8 * sign, Uint32 sign_len,
                      Uint8 * hash, Uint32 hash_len)
{

    X509 *cert = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY_CTX *ctx;
    Uint8 ulRet = 0;

    cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    if (cert == NULL) {
        printf("Certificate null\n");
        return -1;
    }

    pubkey = X509_get_pubkey(cert);
    ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_verify_init(ctx);
    ulRet = EVP_PKEY_verify(ctx, sign, sign_len, hash, hash_len);

    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (cert)
        X509_free(cert);
    if (pubkey)
        EVP_PKEY_free(pubkey);

    return ulRet;
}

Uint8 verifyAttestation(Uint32 session_handle, Uint8 * response,
                        Uint32 response_len)
{

    Uint8 ulRet;
    Uint8 *hash = NULL, *sign;
    BIO *cbio = NULL;
#ifndef _WIN32
    Uint8 cert[4096] = { };
#else
    Uint8 cert[4096] = { 0 };
#endif
    Uint32 certLen = 4096;

    OpenSSL_add_all_digests();
    ERR_load_CRYPTO_strings();

    ulRet =
        Cfm2GetCert(session_handle, PARTITION_CERT_ISSUED_BY_HSM, cert,
                    &certLen);
    if (ulRet) {
        ulRet = 0;
        goto error;
    }
    cbio = BIO_new_mem_buf((void *) cert, certLen);
    if (BIO_eof(cbio)) {
        printf("BIO returned null\n");
        ulRet = 0;
        goto error;
    }
    hash = hashSHA256(response, response_len - RSA_2048_SIGN_SIZE);
    sign = (response + response_len - RSA_2048_SIGN_SIZE);
    ulRet =
        verifySignature(cbio, sign, RSA_2048_SIGN_SIZE, hash, SHA256_SIZE);

  error:
    printf("\n\tAttestation Check : [%s]\n", ulRet ? "PASS" : "FAIL");
    if (hash)
        free(hash);
    if (cbio)
        BIO_free(cbio);
    return !(ulRet);
}

void print_cluster_error(Uint32 request_id, Uint32 * success_count)
{
#ifndef _WIN32
    op_error_state_t err_st[MAX_CLUSTER_SIZE] = { };
#else
    op_error_state_t err_st[MAX_CLUSTER_SIZE] = { 0 };
#endif

    Uint32 ulRet = 0;
    int i = 0;
    Uint32 suc_count = 0;

    ulRet = Cfm2GetReqClusterStatus(session_handle, err_st, request_id);
    if (ulRet == RET_OK) {
        printf("\n\tCluster Status:\n");
        for (i = 0; i < MAX_CLUSTER_SIZE; i++) {
            if (err_st[i].node != -1) {
                printf("\tNode id %d status: 0x%08x : %s\n",
                       err_st[i].node, err_st[i].rc,
                       Cfm2ResultAsString(err_st[i].rc));
                if (err_st[i].rc == RET_OK)
                    suc_count++;
            }
        }
        if (success_count)
            *success_count = suc_count;
    } else
        printf("Couldn't get cluster error info\n");
}


Uint8 *getAttributeString(int type)
{

    switch (type) {

    case OBJ_ATTR_CLASS:
        return (Uint8 *) "OBJ_ATTR_CLASS";
    case OBJ_ATTR_TOKEN:
        return (Uint8 *) "OBJ_ATTR_TOKEN";
    case OBJ_ATTR_PRIVATE:
        return (Uint8 *) "OBJ_ATTR_PRIVATE";
    case OBJ_ATTR_LABEL:
        return (Uint8 *) "OBJ_ATTR_LABEL";
    case OBJ_ATTR_APPLICATION:
        return (Uint8 *) "OBJ_ATTR_APPLICATION";
    case OBJ_ATTR_VALUE:
        return (Uint8 *) "OBJ_ATTR_VALUE";
    case OBJ_ATTR_CERTIFICATE_TYPE:
        return (Uint8 *) "OBJ_ATTR_CERTIFICATE_TYPE";
    case OBJ_ATTR_ISSUER:
        return (Uint8 *) "OBJ_ATTR_ISSUER";
    case OBJ_ATTR_SERIAL_NUMBER:
        return (Uint8 *) "OBJ_ATTR_SERIAL_NUMBER";
    case OBJ_ATTR_KEY_TYPE:
        return (Uint8 *) "OBJ_ATTR_KEY_TYPE";
    case OBJ_ATTR_SUBJECT:
        return (Uint8 *) "OBJ_ATTR_SUBJECT";
    case OBJ_ATTR_ID:
        return (Uint8 *) "OBJ_ATTR_ID";
    case OBJ_ATTR_SENSITIVE:
        return (Uint8 *) "OBJ_ATTR_SENSITIVE";
    case OBJ_ATTR_ENCRYPT:
        return (Uint8 *) "OBJ_ATTR_ENCRYPT";
    case OBJ_ATTR_DECRYPT:
        return (Uint8 *) "OBJ_ATTR_DECRYPT";
    case OBJ_ATTR_WRAP:
        return (Uint8 *) "OBJ_ATTR_WRAP";
    case OBJ_ATTR_UNWRAP:
        return (Uint8 *) "OBJ_ATTR_UNWRAP";
    case OBJ_ATTR_SIGN:
        return (Uint8 *) "OBJ_ATTR_SIGN";
    case OBJ_ATTR_SIGN_RECOVER:
        return (Uint8 *) "OBJ_ATTR_SIGN_RECOVER";
    case OBJ_ATTR_VERIFY:
        return (Uint8 *) "OBJ_ATTR_VERIFY";
    case OBJ_ATTR_VERIFY_RECOVER:
        return (Uint8 *) "OBJ_ATTR_VERIFY_RECOVER";
    case OBJ_ATTR_START_DATE:
        return (Uint8 *) "OBJ_ATTR_START_DATE";
    case OBJ_ATTR_END_DATE:
        return (Uint8 *) "OBJ_ATTR_END_DATE";
    case OBJ_ATTR_MODULUS:
        return (Uint8 *) "OBJ_ATTR_MODULUS";
    case OBJ_ATTR_MODULUS_BITS:
        return (Uint8 *) "OBJ_ATTR_MODULUS_BITS";
    case OBJ_ATTR_PUBLIC_EXPONENT:
        return (Uint8 *) "OBJ_ATTR_PUBLIC_EXPONENT";
    case OBJ_ATTR_PRIVATE_EXPONENT:
        return (Uint8 *) "OBJ_ATTR_PRIVATE_EXPONENT";
    case OBJ_ATTR_PRIME_1:
        return (Uint8 *) "OBJ_ATTR_PRIME_1";
    case OBJ_ATTR_PRIME_2:
        return (Uint8 *) "OBJ_ATTR_PRIME_2";
    case OBJ_ATTR_EXPONENT_1:
        return (Uint8 *) "OBJ_ATTR_EXPONENT_1";
    case OBJ_ATTR_EXPONENT_2:
        return (Uint8 *) "OBJ_ATTR_EXPONENT_2";
    case OBJ_ATTR_COEFFICIENT:
        return (Uint8 *) "OBJ_ATTR_COEFFICIENT";
    case OBJ_ATTR_VALUE_BITS:
        return (Uint8 *) "OBJ_ATTR_VALUE_BITS";
    case OBJ_ATTR_PRIME:
        return (Uint8 *) "OBJ_ATTR_PRIME";
    case OBJ_ATTR_SUBPRIME:
        return (Uint8 *) "OBJ_ATTR_SUBPRIME";
    case OBJ_ATTR_BASE:
        return (Uint8 *) "OBJ_ATTR_BASE";
    case OBJ_ATTR_PRIME_BITS:
        return (Uint8 *) "OBJ_ATTR_PRIME_BITS";
    case OBJ_ATTR_VALUE_LEN:
        return (Uint8 *) "OBJ_ATTR_VALUE_LEN";
    case OBJ_ATTR_EXTRACTABLE:
        return (Uint8 *) "OBJ_ATTR_EXTRACTABLE";
    case OBJ_ATTR_LOCAL:
        return (Uint8 *) "OBJ_ATTR_LOCAL";
    case OBJ_ATTR_TRUSTED:
        return (Uint8 *) "OBJ_ATTR_TRUSTED";
    case OBJ_ATTR_WRAP_WITH_TRUSTED:
        return (Uint8 *) "OBJ_ATTR_WRAP_WITH_TRUSTED";
    case OBJ_ATTR_NEVER_EXTRACTABLE:
        return (Uint8 *) "OBJ_ATTR_NEVER_EXTRACTABLE";
    case OBJ_ATTR_ALWAYS_SENSITIVE:
        return (Uint8 *) "OBJ_ATTR_ALWAYS_SENSITIVE";
    case OBJ_ATTR_MODIFIABLE:
        return (Uint8 *) "OBJ_ATTR_MODIFIABLE";
    case OBJ_ATTR_DESTROYABLE:
        return (Uint8 *) "OBJ_ATTR_DESTROYABLE";
    case OBJ_ATTR_KCV:
        return (Uint8 *) "OBJ_ATTR_KCV";
    case OBJ_ATTR_VENDOR_DEFINED:
        return (Uint8 *) "OBJ_ATTR_VENDOR_DEFINED";
    case OBJ_ATTR_WRAP_TEMPLATE:
        return (Uint8 *) "OBJ_ATTR_WRAP_TEMPLATE";
    case OBJ_ATTR_UNWRAP_TEMPLATE:
        return (Uint8 *) "OBJ_ATTR_UNWRAP_TEMPLATE";
    case OBJ_ATTR_ALL:
        return (Uint8 *) "OBJ_ATTR_ALL";
    case OBJ_ATTR_DERIVE:
        return (Uint8 *) "OBJ_ATTR_DERIVE";

    default:
        printf("%04x\n", type);
        return (Uint8 *) "INVALID_ATTRIBUTE";
    }

}

/****************************************************************************\
 *
 * FUNCTION     : GetCommandLineArgs
 *
 * DESCRIPTION  : converts the buffer into a "argv" like array
 *
 * RETURN VALUE : int
 *
 \****************************************************************************/
char **GetCommandLineArgs(char *buff, int *_argc)
{
    char *delim = " ";
    char *token = 0;
    Uint32 ret;
    *_argc = 1;                 // start at one to include the app name at location 0

    token = strtok(buff, delim);
    while ((token != 0) && (*_argc < VECTOR_SIZE)) {
        vector[*_argc] = CALLOC_WITH_CHECK(1, strlen(token) + 1);
        if (!vector[*_argc]) {
            printf("\n\tInternal Memory Error (GetCommandLineArgs)\n");
            exit(1);
        }
        ret =
            n3fips_strncpy(vector[*_argc], token, strlen(token) + 1,
                           strlen(token));
        if (ret) {
            for (*_argc = 1; *_argc < VECTOR_SIZE; (*_argc)++)
                if (vector[*_argc] != 0) {
                    free(vector[*_argc]);
                    vector[*_argc] = 0;
                }
        }
        (*_argc)++;
        token = strtok(0, delim);
    }

    if (*_argc >= 100)
        *_argc = 1;

    // set the argc value

    return vector;
}

void read_user_ids_from_string(char *buffer, Uint16 * pUsers,
                               Uint8 * pulCount)
{
    char *delim = ",";
    char *token = NULL;
    int i = 0;

    token = strtok(buffer, delim);
    while ((token != NULL) && (i < MAX_USERS_SHARED)) {
        pUsers[i] = atoi(token);
        i++;
        token = strtok(0, delim);
    }
    *pulCount = i;
}

void read_session_ids_from_string(char *buffer, Uint32 * pSessions,
                                  Uint8 * pulCount)
{
    char *delim = ",";
    char *token = NULL;
    int i = 0;

    token = strtok(buffer, delim);
    while ((token != NULL) && (i <= MAX_SESSIONS_SHARED)) {
        pSessions[i] = atoi(token);
        i++;
        token = strtok(0, delim);
    }
    *pulCount = i;
}

/****************************************************************************\
 *
 * FUNCTION     : readFileArg
 *
 * DESCRIPTION  : -
 - reads a string arg from pBuffer
 - to read a file with the file name pBuffer
 - return 1 (true) on success
 - Any file data read will be put at pwTargetLen freed at the end of the command
 as part of clearAndResetDynamicBufferVector
 *
 \****************************************************************************/
Uint8 readFileArg(char *pBuffer, char **pTarget, Uint32 * pwTargetLen)
{
    if ((pBuffer == 0) || (pTarget == 0) || (pwTargetLen == 0))
        return 0;

    // try to read data from file
    if (ReadBinaryFile(pBuffer, (char **) pTarget, pwTargetLen)) {
        // flag this buffer to be cleaned up later
        dyn_vector[ulDynVectorSize] = *pTarget;
        ulDynVectorSize = ulDynVectorSize + 1;
    } else {
        printf
            ("\n\tWARNING: Failed to read from the file \"%s\".\n",
             pBuffer);
        return 0;
    }

    return 1;
}

/*
   CAUTION!!
   This gives a buffer by allocating memory, it is
   the caller responsibility to free that buffer
   */
Uint8 readArgAsString(char *pBuffer, char **pTarget, Uint32 * pwTargetLen)
{
    if ((pBuffer == 0) || (pTarget == 0) || (pwTargetLen == 0))
        return 0;
    *pTarget = calloc(1, strlen(pBuffer) + 1);
    if (!*pTarget) {
        printf("Memory allocation failed\n");
        return FALSE;
    }
    (void) n3fips_strncpy(*pTarget, pBuffer, (strlen(pBuffer) + 1),
                          strlen(pBuffer));
    *pwTargetLen = strlen(pBuffer);
    return 1;
}

#ifndef _WIN32
Uint8 readStringArgByMap(char *pBuffer,
                         char **pTarget,
                         Uint32 * pwTargetLen, Uint32 bFileExpected,
                         char *msg)
{
    if ((pBuffer == 0) || (pTarget == 0) || (pwTargetLen == 0))
        return 0;

    // try to read data from file
    if (ReadFileByMap(pBuffer, (char **) pTarget, pwTargetLen)) {
        // flag this buffer to be cleaned up later
        dyn_vector[ulDynVectorSize] = *pTarget;
        ulDynVectorSize = ulDynVectorSize + 1;
    } else {
        if (bFileExpected)
            if (msg) {
                printf
                    ("\n\tWARNING: Failed to read \"%s\" from the file \"%s\".  Using supplied parameter.\n",
                     msg, pBuffer);
            }
        // Otherwise, the string param was supplied explicitly
        *pTarget = CALLOC_WITH_CHECK(1, strlen(pBuffer) + 1);
        memcpy(*pTarget, pBuffer, strlen(pBuffer) + 1);
        *pwTargetLen = strlen(pBuffer);
    }

    return 1;
}
#endif

static Uint8 validateReadPublicExponentIntegerArg(char *pBuffer, Uint32 *pulValue)
{
    Uint64 tmp_exp;
    int i;

    if ((pBuffer == 0) || (pulValue == 0))
        return 0;

    if (strlen(pBuffer) > ceil(log10(pow(2, sizeof(int) * 8 - 1) - 1))) {
	printf("\n\tError: input length %d is more than %d digits and input is %s\n",
	       (int)strlen(pBuffer),
	       (int)ceil(log10(pow(2, sizeof(int) * 8 - 1) - 1)), pBuffer);
	return 0;
    }
    for (i = 0; i < strlen(pBuffer); i++) {
        if (!isdigit(pBuffer[i])) {
            printf("\n\tError: char %c is not a digit \n", pBuffer[i]);
            return 0;
        }
    }

    tmp_exp = strtoull(pBuffer, NULL, 10);
    if (tmp_exp > (Uint64)(pow(2, sizeof(int) * 8 - 1) - 1)) {
        printf("\n\tError: exponent value %s is more than %lld\n", pBuffer,
	       (Uint64)(pow(2, sizeof(int) * 8 - 1) - 1));
        return 0;
    }
    *pulValue = tmp_exp;

    return 1;
}

/****************************************************************************\
 *
 * FUNCTION     : readIntegerArg
 *
 * DESCRIPTION  : -
 - reads an integer arg from the vector of args
 *
 \****************************************************************************/
Uint8 readIntegerArg(char *pBuffer, Uint32 * pulValue)
{
    int i;

    if ((pBuffer == 0) || (pulValue == 0))
        return 0;

    for (i = 0; i < strlen(pBuffer); i++)
        if (!isdigit(pBuffer[i]))
            return 0;

    *pulValue = atoi(pBuffer);

    return 1;
}

Uint8 readLongIntegerArg(char *pBuffer, Uint64 * pulValue)
{
    int i;

    if ((pBuffer == 0) || (pulValue == 0))
        return 0;

    for (i = 0; i < strlen(pBuffer); i++)
        if (!isdigit(pBuffer[i]))
            return 0;

    *pulValue = strtoull(pBuffer, NULL, 10);

    return 1;
}

Uint8 readIntegerArrayArg(char *pBuffer, Uint32 ** pTarget,
                          Uint32 * pwCount)
{

    char *token = 0;
    char *seps = (char *) ",";
    char *temp = 0;
    int wBufferSizeInBytes = 0;

    if ((pBuffer == 0) || (pTarget == 0) || (pwCount == 0))
        return 0;

    *pwCount = 0;

    //if (GetDynBuffer((void**)&temp, strlen(pBuffer)+1) != CKR_OK)
    temp = (char *) CALLOC_WITH_CHECK(1, strlen(pBuffer) + 1);
    if (!temp)
        return 0;

    strcpy(temp, pBuffer);
    // count the tokens
    token = strtok(temp, seps);
    while (token != NULL) {
        (*pwCount)++;
        //printf( "token: %s\n", token );
        token = strtok(NULL, seps);
    }

    // allocate the buffer for the tokens
    wBufferSizeInBytes = *pwCount * sizeof(Uint32);

    *pTarget = (Uint32 *) CALLOC_WITH_CHECK(1, wBufferSizeInBytes);
    if (!(*pTarget)) {
        if (temp)
            free(temp);
        return 0;
    }

    /*
       if (GetDynBuffer((void**)pTarget, wBufferSizeInBytes) != CKR_OK)
       return 0;
     */

    // populate the array of ints
    *pwCount = 0;
    token = strtok(pBuffer, seps);
    while (token != NULL) {
        (*pTarget)[*pwCount] = atoi(token);
        (*pwCount)++;
        token = strtok(NULL, seps);
    }

    if (temp)
        free(temp);

    return 1;
}

/****************************************************************************\
 *
 * FUNCTION     : main
 *
 * DESCRIPTION  : The "main" function of the Cfm2Util Utility to allow command
 *                line arguments to be used to make Cavium Shim API calls.
 *
 * PARAMETERS   : argc, **argv
 *
 * RETURN VALUE : int
 *
 \****************************************************************************/

FILE *pScriptFile = 0;
int openScriptFile(char *pFileName)
{
    pScriptFile = fopen(pFileName, "r");
    return (pScriptFile == 0);
}

int readLineFromScriptFile(char *pBuffer, unsigned int nBufferSize)
{
    unsigned int nCharsRead = 0;
    char ch;
    if (fread(&ch, 1, 1, pScriptFile) == 0)
        ch = EOF;
    while ((ch != EOF) && (ch != '\n')) {
        if ((ch != '\r') && ((nCharsRead + 1) < nBufferSize)) {
            pBuffer[nCharsRead++] = ch;
        }
        if (fread(&ch, 1, 1, pScriptFile) == 0)
            ch = EOF;
    }
    // Null terminate the string before returning
    pBuffer[nCharsRead] = 0;
    return (ch == EOF);
}

void closeScriptFile()
{
    if (pScriptFile)
        fclose(pScriptFile);
}

int main(int argc, char **argv)
{
    Uint32 ulRet = 0;
    int ret = -1;
#ifndef _WIN32
    char buff[1500] = { };
#else
    char buff[1500] = { '\0' };
#endif
    int bExit = 0;
    char **_argv = 0;
    char *cmd;
    int _argc = 0;

    PartitionInfo partn_info = { {0} };
    Uint32 comp_vers = 0;
    ComponentVersion *peer_ver = NULL;
    ComponentVersion *sdk_ver = NULL;
    ComponentVersion min_ver = { 0 };
    ComponentVersion max_ver = { 0 };

    peer_ver = (ComponentVersion *)&comp_vers;
    sdk_ver = (ComponentVersion *)((Uint8 *)&comp_vers + sizeof(ComponentVersion));
    ulRet = get_version(&comp_vers);

    if(argc > 1 && !strncmp(argv[1], "-v", 2)) {
        printf("Util Version\t\t\t:\t%d.%02d\n", MAJOR_VERSION, MINOR_VERSION);
        printf("SDK API Version\t\t\t:\t%d.%02d\n", sdk_ver->major, sdk_ver->minor);
        if (!ulRet) {
            printf("LiquidSec Client Version\t:\t%d.%02d\n",
				    peer_ver->major, peer_ver->minor);
        }
        Cfm2SDKCleanup();
        return 0;
    }
    if(ulRet) {
        printf("\n\tget_peer_version() returned 0x%02x : %s\n",
               ulRet, Cfm2ResultAsString(ulRet));
    }

    /* validate component versions */
    min_ver.major = MIN_MAJOR_VERSION;
    min_ver.minor = MIN_MINOR_VERSION;
    max_ver.major = MAX_MAJOR_VERSION;
    max_ver.minor = MAX_MINOR_VERSION;
    if(version_compatible(*sdk_ver, min_ver, max_ver) == FAILURE) {
        printf("Version Mismatch with sdk api, "
            "SDK API Version: %d.%d, supported range: %d.%d to %d.%d\n",
            sdk_ver->major, sdk_ver->minor, min_ver.major, min_ver.minor,
            max_ver.major, max_ver.minor);
        Cfm2SDKCleanup();
        return -1;
    }

    // initialize the dynamic buffer vector
    initDynamicBufferVector();

    // initialize the vector
    for (_argc = 1; _argc < VECTOR_SIZE; _argc++)
        vector[_argc] = 0;
    _argc = 0;

    // set the first item to be the name of the app
    vector[0] = argv[0];

    partition_name = "PARTITION_1";

    // Open Interfaces to Driver
    if ((ulRet = Cfm3Initialize(&application_id)) != 0) {
        printf("\n\tCfm3Initialize() returned 0x%02x : %s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        printf("\n\tCfm3Initialize() returned app id : %08x \n",
               application_id);
        goto endUtil;
    }

    printf("\n\tCfm3Initialize() returned app id : %08x \n",
           application_id);
    // Open a session
    if ((ulRet = Cfm3OpenSession(application_id, &session_handle)) != 0) {
        printf("\n\tCfm3OpenSession2() returned 0x%02x : %s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        goto endUtil;
    }
    printf("\n\tsession_handle %x \n", session_handle);    // RAM
    if ((ulRet = Cfm2GetPartitionInfo(session_handle,
                                      (Uint8 *) partition_name,
                                      strlen(partition_name),
                                      &partn_info)) != 0) {
        printf("\n\tCfm3GetPartitionInfo returned: 0x%02x \n\n\t%s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        goto endUtil;
    }


    fipsState = (char) partn_info.FipsState;
    printf("\n\tCurrent FIPS mode is: %08x\n", fipsState);
    // determine if we want to use a scriptfile, a single command, or interactive mode
    if ((argc > 1) && (strcmp(argv[1], "scriptfile") == 0)) {
        if (openScriptFile(argv[2])) {
            printf("\n\tError: Failed to open script file %s. \n",
                   argv[2]);
        } else {
            while (bExit == 0) {
                if (readLineFromScriptFile(buff, 14000))
                    bExit = 1;  // flag the EOF, but still process this line, there could be valid data there

                if (strlen(buff) > 0) {
                    if (buff[0] == '#') {
                        printf("Comment: %s \n", buff);
                    } else {
                        cmd = strstr(buff, "shell");
                        if (cmd != NULL) {
                            cmd = cmd + strlen("shell");
                            while (*cmd == ' ')
                                cmd++;
                            printf("\n%s\n", cmd);
                            system(cmd);
                        } else {
                            printf("Command String: %s \n", buff);
                            _argv = GetCommandLineArgs(buff, &_argc);
                            bExit = CfmUtil_main(_argc, _argv);
                        }
                    }
                }
                // free up any dynamic memory that was allocated when parsing the command and reading file contents
                clearAndResetDynamicBufferVector();

                // clear the vector
                for (_argc = 1; _argc < VECTOR_SIZE; _argc++) {
                    if (vector[_argc] != 0) {
                        free(vector[_argc]);
                        vector[_argc] = 0;
                    }
                }
                _argc = 0;
            }
            closeScriptFile();
        }
    } else if ((argc > 1) && (strcmp(argv[1], "singlecmd") == 0)) {
        int i = 0;
        char *ptr = argv[1];
        int loginArgCount = 0;
        // get rid of the "singlecmd" value by
        // moving all the params back one position in the array
        // and putting "singlecmd" at the last spot.
        // decrement argc, so that its not used by Cfm2_main
        if ((argc > 9) && (strcmp(argv[2], "loginHSM") == 0)) {
            loginArgCount = 9;
            for (i = 2; i < 10; i++) {
                if (strcmp(argv[i], "-2fa") == 0)       //check for dual factor arguments for login
                {
                    loginArgCount = 10;
                    break;
                }
            }
            ulRet = login(loginArgCount - 1, &argv[1]);
            if (ulRet != RET_OK)
                goto endUtil;
            for (i = loginArgCount; i < argc; i++) {
                argv[i - (loginArgCount - 1)] = argv[i];
            }
            argv[i] = ptr;
            argc -= (loginArgCount - 1);

        } else {
            for (i = 2; i < argc; i++) {
                argv[i - 1] = argv[i];
            }
            argv[i] = ptr;
            argc--;
        }
        if (argc > 1) {
            // display the command
            printf("Command:");
            for (i = 1; i < argc; i++)
                printf(" %s ", argv[i]);

            printf("\n");
            CfmUtil_main(argc, argv);   // argc - "Cfm2Util" - "scripting", argv +2
            clearAndResetDynamicBufferVector();
        }
    } else if (argc == 1) {
        Help_AllCommands(vector[0]);

        while (bExit == 0) {
            while (GetConsoleString("\nCommand: ", buff, 1400) == 0) {
            }
            _argv = GetCommandLineArgs(buff, &_argc);
            bExit = CfmUtil_main(_argc, _argv);
            // free up any dynamic memory that was allocated when parsing the command and reading file contents
            clearAndResetDynamicBufferVector();

            // clear the vector
            for (_argc = 1; _argc < VECTOR_SIZE; _argc++)
                if (vector[_argc] != 0) {
                    free(vector[_argc]);
                    vector[_argc] = 0;
                }
            _argc = 0;
        }
    }                           // scripting
    else {
        printf("\n\tError: Unknown commandline arguments. \n");
        printf
            ("\t\tIf you want to script a command, use the following format: \n");
        printf("\t\t\t\"Cfm3Util singlecmd <command>\" \n");
        printf
            ("\t\tWhere <command> is the full command you would type when \n");
        printf
            ("\t\tyou are using Cfm3Util in the normal interactive mode.\n");
        printf("\n\n");
        printf
            ("\t\tIf you want to script a CU authorised command,\n");
        printf("\t\tuse the following format: \n");
        printf
            ("\t\t\t\"Cfm3Util singlecmd [loginHSM -u <CU> -s <username> -p <password>] <command>\" \n");
        printf("\n");
    }
    ret = 0;
  endUtil:
    // Close the Session
    if (session_handle) {
        ulRet = Cfm2CloseSession(session_handle);
        if (ulRet) {
            printf("\n\tCfm3CloseSession returned: 0x%02x \n\n\t%s\n",
                   ulRet, Cfm2ResultAsString(ulRet));
        }
    }
    // Shut Down the Library
    if (application_id) {
        ulRet = Cfm3Shutdown(application_id);
        if (ulRet) {
            printf("\n\tCfm3Shutdown returned: 0x%02x \n\n\t%s\n",
                   ulRet, Cfm2ResultAsString(ulRet));
        }
    }

    EVP_cleanup();
    ERR_remove_state(0);
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return ret;
}

Uint32 listUsers(int argc, char **argv)
{
    Uint32 ulRet = 0;
    UserInfo *users = NULL;
    Uint32 count = 0, total = 0, rem_total = 0;
    int i = 0, found = 0;
    int last_found_user_id = 0;

    if (argc > 2) {
        printf("\n\tThis command doesn't expect any arguments\n");
        printf("\nDescription:");
        printf("\n\tlistUsers lists all users of the current partition\n");
        return ulRet;
    }
    ulRet = Cfm3ListUsers(session_handle, 0, NULL, &count, &total, NULL);
    if (ulRet != RET_OK) {
        printf("\n\tCfm3ListUsers returned: 0x%02x \n\n\t%s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        return ulRet;
    }

    printf("\n\tNumber Of Users Found: %d\n\n", total);

    users =
        (UserInfo *) CALLOC_WITH_CHECK((total + MAX_LIST_USERS_CNT),
                                       sizeof(UserInfo));
    if (users == NULL) {
        printf("Memory allocation failure \n");
        ulRet = ERR_MEMORY_ALLOC_FAILURE;
        return ulRet;
    }
    memset((uint8_t *) users, 0,
           ((total + MAX_LIST_USERS_CNT) * sizeof(UserInfo)));

    rem_total = total;
    do {
        if (rem_total > MAX_LIST_USERS_CNT)
            count = MAX_LIST_USERS_CNT;
        ulRet =
            Cfm3ListUsers(session_handle, last_found_user_id,
                          users + found, &count, &rem_total, NULL);
        if (ulRet != RET_OK)
            break;
        found += count;
        if (found > 1)
            last_found_user_id = betoh32(users[found - 1].userID);
    } while ((found != total) && (rem_total != 0));

    printf
        ("\tIndex\t    User ID    \tUser Type\tUser Name\t\t\t   MofnPubKey\t LoginFailureCnt\t 2FA\n");
    for (i = 0; i < found; i++) {
        printf("\t%d\t%10d\t%s\t\t%-32s\t%3s %15d\t\t %3s\n", i + 1,
               betoh32(users[i].userID),
               userType[betoh32(users[i].ulUserType)],
               users[i].userName,
               (betoh32(users[i].loginFailureCount) & MOFN_PUBKEY_BIT) ?
               "YES" : "NO",
               betoh32(users[i].loginFailureCount) & ~MOFN_PUBKEY_BIT,
               (betoh32(users[i].loginFailureCount) & MFA_BIT) ? "YES" :
               "NO");
    }
    if (users)
        free(users);
    printf("\n\tCfm3ListUsers returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : loginStatus
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 loginStatus(int argc, char **argv)
{
    Uint32 ulRet = 0;
    unsigned int state = 0xFF;

    if (argc > 2) {
        printf
            ("\n\tThis command doesn't expect any arguments and allowed only on initialized HSM\n");
        printf("\nDescription:");
        printf
            ("\n\tloginStatus informs if CU or CO is logged into the initialized HSM through current application.\n");
        return ulRet;
    }

    ulRet = Cfm3GetLoginStatus(session_handle, &state);
    if (ulRet != 0) {
        printf("\n\tCfm3GetLoginStatus Failure: 0x%02x : %s\n", ulRet,
               Cfm2ResultAsString(ulRet));
        return ulRet;
    }
    switch (state) {
    case STATE_RO_PUBLIC_SESSION:
    case STATE_RW_PUBLIC_SESSION:
        {
            printf("\n\tNo user has logged-in\n");
            break;
        }
    case STATE_RO_USER_FUNCTIONS:
    case STATE_RW_USER_FUNCTIONS:
        {
            printf("\n\tCU has logged-in\n");
            break;
        }
    case STATE_RW_APP_USER_FUNCTIONS:
        {
            printf("\n\tAU has logged-in\n");
            break;
        }
    case STATE_RW_CO_FUNCTIONS:
        {
            printf("\n\tCO has logged-in\n");
            break;
        }
    case STATE_RW_PUBLIC_CO_DEFAULT_SESSION:
        {
            printf("\n\t Default CO has logged in\n");
            break;
        }
    default:
        printf("\n\tinvalid state %d\n", state);
        break;
    }
    return 0;
}

/****************************************************************************
 *
 * FUNCTION     : getHSMInfo
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 getHSMInfo(int argc, char **argv)
{
    Uint32 ulRet = 0;
    int temperature = 0;
#ifndef _WIN32
    HSMInfo hsm_info = { };
#else
    HSMInfo hsm_info = { 0 };
#endif

    if (argc > 2) {
        printf("\n\tThis command doesn't expect any arguments\n");
        printf("\nDescription:");
        printf("\n\tgetHSMInfo returns HSM information\n");
        return ulRet;
    }

    ulRet = Cfm3GetHSMInfo(session_handle, &hsm_info);
    if (ulRet != 0) {
        printf("\n\tCfm3GetHSMInfo2 Failure: 0x%02x : %s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        return ulRet;
    }
    printf("\n");
    printf("\tLabel                :%.50s\n", hsm_info.label);
    printf("\tModel                :%s\n", hsm_info.model);
    printf("\tSerial Number        :%s\n", hsm_info.serialNumber);
    printf("\tHSM Flags            :%d\n", hsm_info.uiFlags);
    printf("\tFIPS state           :%d [%s]\n",
           betoh32(hsm_info.uiFipsState),
           fips_state[betoh32(hsm_info.uiFipsState) + 1]);
    printf("\n");
    printf("\tManufacturer ID      : \n");
    printf("\tDevice ID            :%02X\n",
           betoh32(hsm_info.manufacturerID.dev_id));
    printf("\tClass Code           :%02X\n",
           betoh32(hsm_info.manufacturerID.class_code));
    printf("\tSystem vendor ID     :%02X\n",
           betoh32(hsm_info.manufacturerID.vendor_id));
    printf("\tSubSystem ID         :%02X\n",
           betoh32(hsm_info.manufacturerID.subsystem_id));
    printf("\n");
    printf("\n");
    printf("\tTotalPublicMemory    :%d\n", betoh32(hsm_info.uiTotalRAM));
    printf("\tFreePublicMemory     :%d\n", betoh32(hsm_info.uiFreeRAM));
    printf("\tTotalPrivateMemory   :%d\n", betoh32(hsm_info.uiTotalFlash));
    printf("\tFreePrivateMemory    :%d\n", betoh32(hsm_info.uiFreeFlash));
    printf("\n");
    printf("\tHardware Major       :%c\n", hsm_info.hardwareVersion.major);
    printf("\tHardware Minor       :%c\n", hsm_info.hardwareVersion.minor);
    printf("\n");
    printf("\tFirmware Major       :%d\n", hsm_info.firmwareVersion.major);
    printf("\tFirmware Minor       :%02d\n",
           hsm_info.firmwareVersion.minor);
    printf("\n");
    temperature = betoh32(hsm_info.uiTemperature);
    printf("\tTemperature          :%d C\n", (char) temperature);
    printf("\n");
    printf("\tBuild Number         :%s\n", hsm_info.buildNum);
    printf("\n");
    printf("\tFirmware ID          :%s\n", hsm_info.firmwareString + 9);
    printf("\n");

    return ulRet;
}

Uint32 getToken(int argc, char **argv)
{
    Uint32 ulRet = 0;
    int i = 0;
    Uint8 bHelp = FALSE;

	Uint8 bServiceNo = FALSE;
    Uint8 ServiceNo = 0;
    Uint32 ulTemp = 0;
#ifndef _WIN32
    token_t Token[32] = { };
    Uint32 ulTokenLen = 32 * sizeof(token_t);
#else
    token_t Token[32] = { 0 };
    Uint32 ulTokenLen = 32 * sizeof(token_t);
#endif
    Uint8 bKey = FALSE;
    Uint32 KeyToBeApproved = 0;
    Uint8 bName = FALSE;
    Int8 *uName = NULL;
    Uint32 ulNameLen = 0;
    Uint8 bFile = FALSE;
    Int8 *uFile = NULL;
    Uint32 ulFileLen = 0;
    Uint32 request_id = -1;
    Uint32 success_count = 0;
    Uint8 bFlags = FALSE;
    Uint32 flags = 0;
    FILE *fp = NULL;


    for (i = 2; i < argc; i = i + 2) {
        if (!bServiceNo && (strcmp(argv[i], "-n") == 0)
            && (argc > i + 1)) {
            bServiceNo = readIntegerArg(argv[i + 1], &ulTemp);
            ServiceNo = ulTemp;
        } else if (!bKey && (strcmp(argv[i], "-k") == 0)
            && (argc > i + 1)) {
            bKey = readIntegerArg(argv[i + 1], &KeyToBeApproved);
        } else if (!bName && (strcmp(argv[i], "-u") == 0)
                   && (argc > i + 1)) {
            bName = readArgAsString(argv[i + 1], &uName, &ulNameLen);
        } else if (!bFile && (strcmp(argv[i], "-f") == 0)
                   && (argc > i + 1)) {
            bFile = readArgAsString(argv[i + 1], &uFile, &ulFileLen);
        } else if (!bFlags && (strcmp(argv[i], "-F") == 0)
                   && (argc > i + 1)) {
            bFlags = readIntegerArg(argv[i + 1], &flags);
        } else
            bHelp = TRUE;
    }

    if (!bName || !bFile) {
        bHelp = TRUE;
    }

    if (!bHelp && !bKey) {
        if (ServiceNo == USE_KEY || ServiceNo == MANAGE_KEY) {
            printf("\n\tError: Key Handle (-k) is missing.\n");
            bHelp = TRUE;
        }
    }

    if (ServiceNo < USE_KEY || ServiceNo > MANAGE_KEY) {
        printf("Invalid service number\n");
        bHelp = TRUE;
    }

    if (bName && (ulNameLen > MAX_NAME_LEN)) {
        bHelp = TRUE;
    }

    if (bFlags && (flags != RECREATE_IF_TOKEN_TIMED_OUT)) {
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nInitiates an MxN auth service and returns a token");
        printf("\n");
        printf
            ("\nSyntax: getToken -n <ServiceNo> -k <Key> -u <user_name> -f <token_file_to_store> [-F flags]");
        printf("\n");
        printf("\nWhere: -h  displays this information   ");
        printf("\n       -n  Service Number");
        for (i = USE_KEY; i < MAX_MXN_AUTH_SERVICES; i++) {
            printf("\n\t\t%d - %s", i, services[i]);
        }
        printf("\n       -k  Key to be approved");
        printf("\n       -u  user name");
        printf("\n       -f  File name to write the token");
        printf("\n       -F   flags");
        printf
            ("\n       4 - Clean and create token if there are no free tokens");
        printf("\n           and existing tokens are timedout\n");
        printf("\n");
        goto exit;
    }

    fp = fopen(uFile, "wb");
    if (!fp) {
        printf("failed to open the file %s\n", uFile);
        goto exit;
    }

    ulRet = Cfm2GetToken2(session_handle,
                          ServiceNo, KeyToBeApproved, uName,
                          Token, &ulTokenLen, flags, NULL, &request_id);
    printf("\n\tCfm3GetToken returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    if (ulRet == RET_OK || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        size_t len = 0;

        len = fwrite((char *) &Token, 1, ulTokenLen, fp);
        if (len != ulTokenLen) {
            printf
                ("coudn't write all token info, %zu byte written of %u\n",
                 len, ulTokenLen);
        }
        Cfm2PrintToken(Token, ulTokenLen, 0);
        fclose(fp);
        fp = NULL;
    }
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
  exit:
    if (uName)
        free(uName);
    if (uFile)
        free(uFile);
    if (fp)
        fclose(fp);
    return ulRet;
}

Uint32 delToken(int argc, char **argv)
{
    Uint32 ulRet = 0;
    int i = 0;
    Uint8 bHelp = FALSE;

    token_t *pToken = NULL;
    Uint8 bToken = FALSE;
    Uint32 ulTokenLen = 0;
    Uint32 ulDelFlags = 0;
    Uint8 bFlags = FALSE;
    Uint32 request_id = -1;
    Uint32 success_count = 0;

    for (i = 2; i < argc; i = i + 2) {
        if (!bToken && (strcmp(argv[i], "-tf") == 0)
            && (argc > i + 1)) {
            bToken =
                readFileArg(argv[i + 1], (char **) &pToken, &ulTokenLen);
        } else if (!bFlags && (strcmp(argv[i], "-f") == 0)
                   && (argc > i + 1)) {
            bFlags = readIntegerArg(argv[i + 1], &ulDelFlags);
        } else if (strcmp(argv[i], "-h") == 0) {
            bHelp = TRUE;
            break;
        } else
            bHelp = TRUE;
    }


    if (bFlags && ulDelFlags != 4)
        bHelp = TRUE;

    if (!bToken && !bFlags) {
        bHelp = TRUE;
    }
    if (bToken && (ulTokenLen % sizeof(token_t) != 0)) {
        bHelp = TRUE;
        printf("Improper token passed\n");
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\ndelete one or more  mofn token");
        printf("\n");
        printf("\nSyntax: delToken -tf <token file> || -f <delete flags>");
        printf("\n");
        printf("\nWhere: -h   displays this information   ");
        printf("\n       -tf  token to be deleted");
        printf("\n       -f   Delete Flags ");
        printf("\n            - 4 for all tokens of user");
        printf("\n");
        goto exit;
    }

    ulRet = Cfm2DeleteToken2(session_handle,
                             pToken, ulTokenLen, ulDelFlags, NULL,
                             &request_id);
    printf("\n\tCfm3DeleteToken returned: 0x%02x %s%s\n", ulRet,
           ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
  exit:
    return ulRet;
}


Uint32 approveToken(int argc, char **argv)
{
    Uint32 ulRet = 0;
    int i = 0, cnt = 0;
    Uint32 *resp = NULL;
#ifndef _WIN32
    char tf[256] = { 0 }, mtf[256] = {
    0};
#else
    char tf[256] = { '\0' }, mtf[256] = {
    '\0'};
#endif
    char buf[512] = { 0 };
    Uint32 nt = 0, na = 0;
    FILE *fp = NULL;

    FILE *tFile = NULL;
    Uint32 l_mtf = 0, l_af = 0;
    bool bHelp = FALSE, b_af = FALSE;
    char *af = NULL;
    token_t *t = NULL;
    Uint8 *t_blob = NULL, *a_blob = NULL;
    Uint32 request_id = -1;
    Uint32 success_count = 0;
    mofn_approval_t *app;

    for (i = 2; i < argc; i = i + 2) {
        if (strcmp(argv[i], "-h") == 0) {
            bHelp = TRUE;
            break;
        } else if (!b_af && (strcmp(argv[i], "-af") == 0)
                   && (argc > i + 1)) {
            b_af = readArgAsString(argv[i + 1], (char **) &af, &l_af);
        } else
            bHelp = TRUE;
    }

    if (!b_af)
        bHelp = TRUE;

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nApproves an MxN protected service identified by Token");
        printf("\n");
        printf
            ("\nSyntax: approveToken -h -af <approval-template-file> ");
        printf("\n");
        printf("\nWhere: -h   displays this information   ");
        printf("\n       -af  approval blob file");
        printf("\n");
        goto end;
    }
    tFile = fopen(af, "r");
    if (tFile == NULL) {
        printf("Failed to open file: %s\n", af);
        ulRet = -1;
        goto end;
    }

    cnt = 0;
    while (cnt < 3 && fgets(buf, sizeof(buf), tFile)) {
        getFieldStr(buf, "Token File Path", tf, sizeof(tf), cnt);
        getFieldStr(buf, "Multi Token File Path", mtf, sizeof(mtf), cnt);
        getField(buf, "Number of Approvals", &na, Uint32, cnt);
        memset(buf, 0, sizeof(buf));
    }

    if (tf[0] == 0)
        goto skip_token;
    fp = fopen((const char *) tf, "r");
    if (!fp) {
        printf("failed to open %s\n", tf);
        goto end;
    }
    t = CALLOC_WITH_CHECK(1, sizeof(token_t));

    if (1 != fread((char *) t, sizeof(token_t), 1, fp)) {
        printf("failed to read token from %s\n", tf);
        fclose(fp);
        fp = NULL;
        goto end;
    }

    fclose(fp);
    fp = NULL;

  skip_token:
    
    fp = fopen((const char *) mtf, "r");
    if (!fp) {
         printf("failed to open %s\n", mtf);
         goto end;
    }

    /*
     * In case of HA, user may not know the number of tokens in the blob.
     * Compute num tokens based on the file size.
     */
    fseek(fp, 0, SEEK_END);
    l_mtf = ftell(fp);
    rewind(fp);
	
    if (l_mtf % sizeof(token_t) != 0) {
        printf("%s(): Invalid Token Size: %d\n", __func__, l_mtf);
	fclose(fp);
        goto end;
    }
    nt = l_mtf / sizeof(token_t);

    if (na > 20) {
        printf(" number of approvals in the file is more than 20\n");
	fclose(fp);
        goto end;
    }
    if (nt > 32) {
        printf(" number of tokens in the file is more than 32\n");
	fclose(fp);
        goto end;
    }

    t_blob = CALLOC_WITH_CHECK(1, l_mtf);

    if ((nt == 1) && t) {
        memcpy(t_blob, (char *) t, l_mtf);
    } else {
        if (nt != fread((char *) t_blob, sizeof(token_t), nt, fp)) {
            printf("failed to read %d tokens from %s\n", nt, mtf);
            fclose(fp);
            fp = NULL;
            goto end;
        }
    }
    fclose(fp);
    fp = NULL;

    memset(buf, 0, sizeof(buf));
    a_blob = calloc(1, na * sizeof(mofn_approval_t));

    /* now read the approval data */
    app = (mofn_approval_t *) a_blob;
    for (i = 0; i < na; i++) {
        char af[256] = { 0 };
        cnt = 0;
        while (cnt < 3) {
			if ((fgets(buf, sizeof(buf), tFile) == NULL) &&
					(i < na)) {
                printf("Failed to read Approver Details\n");
				printf("Could only read %d/%d approvers info\n",
                                                        i, na);
				goto end;
			}
            getField(buf, "Approver Type", &(app->u_type), uint8_t, cnt);
            getFieldStr(buf, "Approver Name", (char *) app->a_name,
                        MAX_NAME_LEN, cnt);
            getFieldStr(buf, "Approval File", af, sizeof(af), cnt);
            memset(buf, 0, sizeof(buf));
        }
        if (cnt != 3) {
            printf("Failed to read Approver Details\n");
            printf("Could only read %d/3 fields for tok %d/%d",
                                                   cnt, i, na);
            goto end;
        }
        //    printf("Approval File = %s\n", af);
        //    printf(" Approver Type = %u and name = %s\n", app->u_type, app->a_name);
        if (app->u_type != CN_CRYPTO_OFFICER
            && app->u_type != CN_CRYPTO_USER) {
            printf("Invalid User Type %d for %s\n", app->u_type,
                   app->a_name);
            goto end;
        }

        fp = fopen((const char *) af, "rb");
        if (!fp) {
            printf("failed to open %s\n", af);
            goto end;
        }
        if (1 != fread(app->approval, MOFN_APPROVAL_SIZE, 1, fp)) {
            printf("failed to read approval from %s\n", af);
            fclose(fp);
            fp = NULL;
            goto end;
        }
        fclose(fp);
        fp = NULL;
        memset(af, 0, sizeof(af));
        app += 1;
    }

    resp = malloc(na * sizeof(Uint32));

    ulRet = Cfm2ApproveToken2(session_handle,
                              t, nt, t_blob, na, a_blob, resp,
                              NULL, &request_id);
    printf("\n\tCfm3ApproveToken returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }

  end:
    if (tFile) {
        fclose(tFile);
        tFile = NULL;
    }
    if (resp) {
        free(resp);
        resp = NULL;
    }
    if (t) {
        free(t);
        t = NULL;
    }
    if (a_blob) {
        free(a_blob);
        a_blob = NULL;
    }
    if (t_blob) {
        free(t_blob);
        t_blob = NULL;
    }
    if (af)
        free(af);
    //if (cmd) {free(cmd); cmd = NULL;}
    return ulRet;
}



#define MAX_PKT_SIZE 8836
Uint32 listTokens(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint8 bHelp = FALSE;
    token_info_t *ti = NULL;
    Uint32 ti_info_size = 0;
    Uint32 num_tokens = 0;
    Uint32 request_id = -1;
    Uint32 success_count = 0;

    if (argc > 2) {
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nGets all approved tokens");
        printf("\n");
        printf("\nSyntax: listTokens");
        printf("\n");
        printf("\nWhere: -h   displays this information   ");
        printf("\n");
        return -1;
    }

  retry:
    ulRet = Cfm2ListTokens2(session_handle,
                            ti, &ti_info_size, &num_tokens, NULL,
                            &request_id);
    if (ulRet != RET_RESULT_SIZE)
        printf("\n\tCfm3ListTokens returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    if (ulRet == RET_OK || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        if (0 == num_tokens)
            printf("no tokens found\n");
        else
            Cfm2PrintTokenInfo((uint8_t *) ti, ti_info_size, num_tokens);
    } else if (ulRet == RET_RESULT_SIZE) {
        if (ti) {
            free(ti);
            ti = NULL;
        }
        if (ti_info_size > MAX_PKT_SIZE)
            ti_info_size = MAX_PKT_SIZE;
        ti = CALLOC_WITH_CHECK(1, ti_info_size);
        if (ti == NULL) {
            printf("%s(): Unable to allocate memory of size %u\n",
                   __func__, ti_info_size);
            return -ENOMEM;
        }
        goto retry;
    }

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }

    if (ti)
        free(ti);
    return ulRet;
}

#ifndef _WIN32
Uint32 registerMofnPubKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bUserType = FALSE;
    char *pUserType = 0;
    Uint32 ulUserTypeLen = 0;
    Uint32 ulUserType = 0;

    Uint8 bNewUserPswd = FALSE;
    char *pNewUserPswd = 0;
    Uint32 ulNewUserPswdLen = 0;

    Uint8 bName = FALSE;
    char *pUserName = 0;
    Uint32 ulNameLen = 0;

    Uint8 bRsaKeyFile = FALSE;
    char *pRsaKeyFile = 0;
    Uint32 ulRsaKeyFileLen = 0;

    Uint8 *pPublicKey = NULL;
    Uint8 *pSignature = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;
    uint32_t sig_length = PSWD_ENC_KEY_MODULUS;
    RSA *rsa = NULL;
#ifndef _WIN32
    uint8_t digest[SHA256_DIGEST_LENGTH] = { };
#else
    uint8_t digest[SHA256_DIGEST_LENGTH] = { 0 };
#endif
    Uint32 request_id = -1;
    Uint32 success_count = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // user type
        else if ((!bUserType) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1))
            bUserType =
                readArgAsString(argv[i + 1], &pUserType, &ulUserTypeLen);

        // new pin
        else if ((!bNewUserPswd) && (strcmp(argv[i], "-n") == 0)
                 && (argc > i + 1))
            bNewUserPswd =
                readArgAsString(argv[i + 1], &pNewUserPswd,
                                &ulNewUserPswdLen);
        // name
        else if ((!bName) && (strcmp(argv[i], "-s") == 0)
                 && (argc > i + 1))
            bName = readArgAsString(argv[i + 1], &pUserName, &ulNameLen);
        // private key
        else if ((!bRsaKeyFile) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1)) {
            if (strlen(argv[i + 1]) > 256)
                bHelp = TRUE;
            else
                bRsaKeyFile =
                    readArgAsString(argv[i + 1], &pRsaKeyFile,
                                    &ulRsaKeyFileLen);
        }
    }

    // ensure that we have all the required args
    if (!bHelp && !bUserType) {
        printf("\n\tError: User Type (-u) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bNewUserPswd) {
        printf("\n\tError: New password (-n) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bName) {
        printf("\n\tError: User name (-s) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bRsaKeyFile) {
        printf("\n\tError: User name (-s) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && bUserType) {
        if ((strcmp(pUserType, "CO") == 0))
            ulUserType = CN_CRYPTO_OFFICER;
        else if ((strcmp(pUserType, "CU") == 0))
            ulUserType = CN_CRYPTO_USER;
        else if ((strcmp(pUserType, "AU") == 0))
            ulUserType = CN_APPLIANCE_USER;
        else if ((strcmp(pUserType, "PO") == 0))
            ulUserType = CN_CRYPTO_PRE_OFFICER;

        else {
            printf("\n\tError: Invalid user type specified.\n");
            bHelp = TRUE;
        }
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nRegister user's MofN public key.");
        printf("\n");
        printf
            ("\nSyntax: registerMofnPubKey -h -u <user_type> -n <auth_tag> -s <user name> -k <private key file>");
        printf("\n\n");
        printf("\nWhere: -h  displays this information");
        printf
            ("\n       -u  specifies the user type as \"CO(for CO/PCO)\" or \"CU\" ");
        printf
            ("\n       -n  <any char string> specifies the authentication tag, ");
        printf("\n       -s  specifies the user name");
        printf
            ("\n       -k RSA 2K private key file path (upto 256 bytes)");
        printf("\n");
        goto end;
    }

    fp = fopen(pRsaKeyFile, "rb");
    if (fp == NULL) {
        printf("Unable to open file %s\n\n", pRsaKeyFile);
        goto end;
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if ((pkey == NULL) || (pkey->type != EVP_PKEY_RSA)) {
        printf("Failed to read private key from %s\n\n", pRsaKeyFile);
        goto end;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        printf("Invalid RSA Key in %s\n\n", pRsaKeyFile);
        goto end;
    }
    // encryption not required for the tag.
#if 0
    ulRet = encrypt_pswd(session_handle,
                         (Uint8 *) pNewUserPswd, ulNewUserPswdLen,
                         pEncPswd, &ulEncPswdLen, NULL, 0);
    if (ulRet != RET_OK) {
        printf("password encryption failed ulRet %d: %s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        goto end;
    }
#endif
    pPublicKey = CALLOC_WITH_CHECK(1, PSWD_ENC_KEY_MODULUS * 2);
    pSignature = CALLOC_WITH_CHECK(1, PSWD_ENC_KEY_MODULUS);
    if ((pSignature == NULL) || (pPublicKey == NULL)) {
        printf("\n\t Failed to allocate memory\n");
        ulRet = ERR_MEMORY_ALLOC_FAILURE;
        goto end;
    }

    BN_bn2bin(rsa->n, (Uint8 *) pPublicKey);
    BN_bn2bin(rsa->e,
              (Uint8 *) pPublicKey + 2 * PSWD_ENC_KEY_MODULUS -
              BN_num_bytes(rsa->e));

    if (!EVP_Digest
        (pNewUserPswd, ulNewUserPswdLen, digest, NULL, EVP_sha256(),
         NULL)) {
        printf("\n\t Digest creation failure\n");
        ulRet = ERR_GENERAL_ERROR;
        goto end;
    }

    if (RSA_sign
        (NID_sha256, digest, SHA256_DIGEST_LENGTH, pSignature, &sig_length,
         rsa) == 0) {
        printf("\n\t RSA sign failure\n");
        ulRet = ERR_GENERAL_ERROR;
        goto end;
    }

    ulRet = Cfm2RegisterMofNKey2(session_handle,
                                 ulUserType,
                                 (Uint8 *) pUserName, ulNameLen,
                                 (Uint8 *) pNewUserPswd,
                                 ulNewUserPswdLen, pPublicKey, pSignature,
                                 NULL, &request_id);

    printf("\n\tCfm3RegisterMofNKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }

  end:
    if (pSignature)
        free(pSignature);
    if (pPublicKey)
        free(pPublicKey);
    if (rsa)
        RSA_free(rsa);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (fp)
        fclose(fp);
    if (pNewUserPswd)
        free(pNewUserPswd);
    if (pUserName)
        free(pUserName);
    if (pUserType)
        free(pUserType);
    if (pRsaKeyFile)
        free(pRsaKeyFile);
    return ulRet;
}
#endif


/****************************************************************************
 *
 * FUNCTION     : getPartitionInfo
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 getPartitionInfo(int argc, char **argv)
{
    Uint32 ulRet = 0;
#ifndef _WIN32
    PartitionInfo info = { };
#else
    PartitionInfo info = { 0 };
#endif
    int i = 0;

    if (argc > 2) {
        printf("\n\tThis command doesn't expect any arguments\n");
        printf("\nDescription:");
        printf("\n\tgetPartitionInfo returns Partition's information\n");
        return ulRet;
    }

    printf("\n\tGetting Partition Info");
    ulRet = Cfm3GetPartitionInfo(session_handle, &info, NULL);
    if (ulRet != 0) {
        printf("\n\tCfm3GetPartitionInfo returned: 0x%02x \n\n\t%s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        return ulRet;
    }

    printf("\n");
    printf("\tname                        :%s  \n", info.name);
    printf("\tstatus                      :%s  \n",
           ((info.status == 0) ? "free" : "occupied"));
    printf("\tFIPS state                  :%d [%s]\n",
           ((char) info.FipsState), fips_state[(char) info.FipsState + 1]);
    printf("\tMaxUsers                    :%5d \n",
           betoh16(info.MaxUsers));
    printf("\tAvailableUsers              :%5d \n",
           betoh16(info.AvailableUsers));
    printf("\tMaxKeys                     :%5d \n", betoh32(info.MaxKeys));
    printf("\tOccupiedTokenKeys           :%5d \n",
           betoh32(info.OccupiedTokenKeys));
    printf("\tOccupiedSessionKeys         :%5d \n",
           betoh32(info.OccupiedSessionKeys));
    printf("\tTotalSSLCtxs                :%5d \n",
           betoh32(info.MaxSSLContexts));
    printf("\tOccupiedSSLCtxs             :%5d \n",
           betoh32(info.OccupiedSSLContexts));
    printf("\tMaxAcclrDevCount            :%5d \n", info.MaxAcclrDevs);
    printf("\tSessionCount                :%5d \n",
           betoh32(info.SessionCount));
    printf("\tMaxPswdLen                  :%5d \n",
           betoh32(info.MaxPinLen));
    printf("\tMinPswdLen                  :%5d \n",
           betoh32(info.MinPinLen));
    printf("\tCloningMethod               :%5d \n", info.CloningMethod);
    printf("\tKekMethod                   :%5d \n", info.KekMethod);
    printf("\tCertAuth                    :%5d \n", info.certAuth);
    printf("\tBlockDeleteUserWithKeys     :%5d \n",
           info.block_delete_user);
    printf("\tTwoKeyBackup                :%5d \n", info.backup_by_mco);
    printf("\tNvalue                      :%5d \n", betoh16(info.NValue));
    for (i = 1; i < MAX_MXN_AUTH_CO_SERVICES; i++)
        printf("\tMValue[%12s]        :%5d \n", services[i],
               info.MValue[i]);
    printf("\tNode ID                     :%5d \n", betoh32(info.node_id));
    printf("\tGroup ID                    :%s \n", info.g_id);
    printf("\tExport with user keys\n"
           "\t (Other than KEK)           : %s \n",
           (htobe32(info.partn_policy_bits) & 0x0f) ? "Enabled" :
           "Disabled");
    printf("\tMCO backup/restore          : %s \n",
           (htobe32(info.partn_policy_bits) & 0xf0) ? "Enabled" :
           "Disabled");
    printf("\tAudit Log Status            : %s \n",
           (info.hsmAuditEnable) ? audit_status_str[info.AuditStatus] :
           "Disabled");
    printf("\tPCO fixed key fingerprint   : ");
    cavium_dump_int_line(info.PCO_key_fingerprint,
                         FIXED_KEY_FINGERPRINT_SIZE);
    printf("\n");

    return ulRet;
}

#if 1
/****************************************************************************
 *
 * FUNCTION     : login
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 login(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;
    Uint8 b2fa = FALSE;

    Uint8 bPassword = FALSE;
    char *pPassword = 0;
    Uint32 ulPasswordLen = 0;

    Uint8 bUserType = FALSE;
    char *pUserType = 0;
    Uint32 ulUserTypeLen = 0;
    Uint32 ulUserType = 0;

    Uint8 bUserName = FALSE;
    char *pUserName = 0;
    Uint32 ulUserNameLen = 0;

    Uint32 request_id = -1;
    Uint32 success_count = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        else if (strcmp(argv[i], "-2fa") == 0) {
            b2fa = TRUE;
            i = i - 1;
        }

        //  password
        else if ((!bPassword) && (strcmp(argv[i], "-p") == 0)
                 && (argc > i + 1))
            bPassword =
                readArgAsString(argv[i + 1], &pPassword, &ulPasswordLen);

        //  user type
        else if ((!bUserType) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1))
            bUserType =
                readArgAsString(argv[i + 1], &pUserType, &ulUserTypeLen);

        //  user name
        else if ((!bUserName) && (strcmp(argv[i], "-s") == 0)
                 && (argc > i + 1))
            bUserName =
                readArgAsString(argv[i + 1], &pUserName, &ulUserNameLen);


        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bUserType) {
        printf("\n\tError: User type (-u) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bPassword) {
        printf("\n\tError: Password (-p) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && bUserType) {
        if ((strcmp(pUserType, "CO") == 0))
            ulUserType = CN_CRYPTO_OFFICER;
        else if ((strcmp(pUserType, "CU") == 0) && b2fa)
            ulUserType = CN_2FA_CRYPTO_USER;
        else if ((strcmp(pUserType, "CU") == 0))
            ulUserType = CN_CRYPTO_USER;
        else if ((strcmp(pUserType, "AU") == 0))
            ulUserType = CN_APPLIANCE_USER;
        else if ((strcmp(pUserType, "PO") == 0) ||
                 (strcmp(pUserType, "PRECO") == 0))
            ulUserType = CN_CRYPTO_PRE_OFFICER;

        else {
            printf("\n\tError: Invalid user type specified.\n");
            bHelp = TRUE;
        }
    }
    if (!bHelp && !bUserName) {
        printf("\n\tError: Username (-s) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nLogin to the HSM providing the user type and password.");
        printf("\n");
        printf
            ("\nSyntax: loginHSM -h -u <user type> -p <password> -s <username> [-2fa]");
        printf("\n\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -u  specifies the user type as \"CU\"");
        printf("\n       -s  specifies the user name");
        printf("\n       -p  specifies the user password");
        printf
            ("\n       -2fa <optional> specifies to use dual factor auth");
        printf("\n");
        goto exit;
    }

    ulRet = Cfm3LoginHSM(session_handle,
                         ulUserType,
                         (Uint8 *) pUserName, ulUserNameLen,
                         (Uint8 *) pPassword, ulPasswordLen, &request_id);

    printf("\n\tCfm3LoginHSM returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }

  exit:
    if (pPassword)
        free(pPassword);
    if (pUserName)
        free(pUserName);
    if (pUserType)
        free(pUserType);
    return ulRet;
}
#endif

/****************************************************************************
 *
 * FUNCTION     : logout
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 logout(int argc, char **argv)
{
    Uint32 ulRet = 0;

    Uint32 request_id = -1;
    Uint32 success_count = 0;

    if (argc > 2) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nLogout from the HSM.");
        printf("\n");
        printf("\nSyntax: logoutHSM -h\n");
        printf("\n");
        printf("\nWhere: -h  displays this information");
        printf("\n");
        return ulRet;
    }
    ulRet = Cfm3LogoutHSM(session_handle, &request_id);
    printf("\n\tCfm3LogoutHSM returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : genECCKeyPair
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 genECCKeyPair(int argc, char **argv)
{

    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    int k=0;
    Uint8 bCurveId = FALSE;
    Uint32 ulCurveId = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulCount = 0;

    Uint8 bMValue = FALSE;
    Uint8 ulMValue = 1;

    Uint64 ulECCPublicKey = 0;
    Uint64 ulECCPrivateKey = 0;

    Uint32 attest = FALSE;
    KeyGenAttest *attest_info = NULL;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 success_count2 = 0;
    Uint32 request_id = -1;

    Uint8 bNextractable = FALSE;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // CurveId
        else if ((!bCurveId) && (strcmp(argv[i], "-i") == 0)
                 && (argc > i + 1)) {
            bCurveId = readIntegerArg(argv[i + 1], &ulCurveId);
            ulCurveId = get_openssl_curve_id(ulCurveId);
            if (!ulCurveId) {
                printf("\n\tError: Invalid EC Curve ID.\n");
                printf("\nThe following are the HSM supported ECC Curves");
                printf("\n");
                printf("\n      NID_X9_62_prime192v1     - 1");
                printf("\n      NID_X9_62_prime256v1     - 2");
                printf("\n      NID_sect163k1            - 3");
                printf("\n      NID_sect163r2            - 4");
                printf("\n      NID_sect233k1            - 5");
                printf("\n      NID_sect233r1            - 6");
                printf("\n      NID_sect283k1            - 7");
                printf("\n      NID_sect283r1            - 8");
                printf("\n      NID_sect409k1            - 9");
                printf("\n      NID_sect409r1            - 10");
                printf("\n      NID_sect571k1            - 11");
                printf("\n      NID_sect571r1            - 12");
                printf("\n      NID_secp224r1            - 13");
                printf("\n      NID_secp384r1            - 14");
                printf("\n      NID_secp521r1            - 15");
                printf("\n      NID_secp256k1            - 16");
                printf("\n");
                goto exit_error;
            }
        }
        // Label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            char *pTemp = NULL;
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulCount);
            if (pTemp)
                free(pTemp);
        } else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        } else if (strcmp(argv[i], "-nex") == 0) {
            bNextractable = TRUE;
            i--;
        }


        else if ((!bMValue) && (strcmp(argv[i], "-m_value") == 0)
                 && (argc > i + 1)) {
            ulMValue = atoi(argv[i + 1]);
            bMValue = TRUE;
            if (ulMValue > MAX_USERS_SHARED)
                bHelp = TRUE;
        } else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                   && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        } else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                   && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else if (strcmp(argv[i], "-attest") == 0) {
            attest = TRUE;
            i--;
        }

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bCurveId) {
        printf("\n\tError: Curve id (-i) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if ((STORAGE_RAM == ucKeyLocation) && bUsers) {
        printf("\n\tError: sharing session keys is not allowed\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nGenerate ECC key pair specifying the curve id");
        printf("\nand key label.");
        printf("\n");
        printf
            ("\nSyntax: genECCKeyPair -h -i <EC curve id> -l <label>\n");
        printf("\t\t\t [-sess] [-nex] [-id <key ID>]\n");
        printf("\t\t\t [-u <user-ids>] [-m_value <0..8>] [-attest]\n");
        printf
            ("\t\t\t [-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h        displays this information");
        printf("\n       -i        specifies the Curve ID");
        printf("\n       -l        specifies the key label");
        printf("\n       -sess     specifies key as session key");
        printf("\n       -id       specifies key ID");
        printf("\n       -nex      set the key as non-extractable");
        printf
            ("\n       -u        specifies the list of users to share with (separated by ,) (optional)");
        printf
            ("\n       -m_value  specifies the number of users to approve for any key service");
        printf
            ("\n       -attest   performs the attestation check on the firmware response");
        printf
            ("\n       -min_srv  specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                 (till the time specified by -timeout option)");
        printf
            ("\n                 if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout  specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                 If nothing is specified, the polling will continue forever\n");
        printf("\n\nThe following are the HSM supported ECC Curves");
        printf("\n");
        printf("\n      NID_X9_62_prime192v1     - 1");
        printf("\n      NID_X9_62_prime256v1     - 2");
        printf("\n      NID_sect163k1            - 3");
        printf("\n      NID_sect163r2            - 4");
        printf("\n      NID_sect233k1            - 5");
        printf("\n      NID_sect233r1            - 6");
        printf("\n      NID_sect283k1            - 7");
        printf("\n      NID_sect283r1            - 8");
        printf("\n      NID_sect409k1            - 9");
        printf("\n      NID_sect409r1            - 10");
        printf("\n      NID_sect571k1            - 11");
        printf("\n      NID_sect571r1            - 12");
        printf("\n      NID_secp224r1            - 13");
        printf("\n      NID_secp384r1            - 14");
        printf("\n      NID_secp521r1            - 15");
        printf("\n      NID_secp256k1            - 16");
        printf("\n\n");
        goto exit_error;
    }
    if (attest) {
        attest_info = calloc(sizeof(*attest_info), 1);

        if (!attest_info) {
            printf("couldn't allocate attest info\n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto error;
        }
    }
    for (k=0;k<100;k++){
    ulRet = Cfm3GenerateKeyPair(session_handle,
                                KEY_TYPE_ECDSA,
                                0, 0, ulCurveId,
                                (Uint16 *) pUsers, ulCount, ulMValue,
                                (Uint8 *) pID, ulIDLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                ucKeyLocation, !bNextractable,
                                (Uint64 *) & ulECCPublicKey,
                                (Uint64 *) & ulECCPrivateKey,
                                attest_info, &request_id);
  error:
    printf("\n\tCfm3GenerateKeyPair returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf
            ("\n\tCfm3GenerateKeyPair:    public key handle: %llu    private key handle: %llu\n",
             (Uint64) ulECCPublicKey, (Uint64) ulECCPrivateKey);
        if (attest) {
            verifyAttestation(session_handle, (Uint8 *) attest_info,
                              sizeof(*attest_info));
        }
    }
    }
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if ((success_count >= ucMinServers
                 && success_count2 >= ucMinServers)
                || ((ulTimeoutValue != 0)
                    && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking private key status (%d seconds)..\n",
                   time_taken);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulECCPrivateKey,
                                  &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
            printf("\n\tChecking public key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulECCPublicKey,
                                  &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count2);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle,
                                  ulECCPublicKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
            ulRet = Cfm3DeleteKey(session_handle,
                                  ulECCPrivateKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);

        } else
            printf
                ("\n\tCfm3GenerateKeyPair:    public key handle: %llu    private key handle: %llu\n",
                 (Uint64) ulECCPublicKey, (Uint64) ulECCPrivateKey);

    }

  exit_error:
    if (attest_info)
        free(attest_info);
    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : genDSAKeyPair
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 genDSAKeyPair(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bMod = FALSE;
    Uint32 ulModLen = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulCount = 0;

    Uint8 bMValue = FALSE;
    Uint8 ulMValue = 1;

    Uint64 ulDSAPublicKey = 0;
    Uint64 ulDSAPrivateKey = 0;

    Uint8 attest = FALSE;
    Uint32 fips_state = 0;
    PartitionInfo partn_info = { {0} };
    KeyGenAttest *attest_info = NULL;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;

    Uint32 success_count2 = 0;


    Uint8 bNextractable = FALSE;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // Mod
        else if ((!bMod) && (strcmp(argv[i], "-m") == 0)
                 && (argc > i + 1))
            bMod = readIntegerArg(argv[i + 1], &ulModLen);

        // Label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            char *pTemp = NULL;
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulCount);
            if (pTemp)
                free(pTemp);
        }

        else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        }

        else if ((!bMValue) && (strcmp(argv[i], "-m_value") == 0)
                 && (argc > i + 1)) {
            ulMValue = atoi(argv[i + 1]);
            bMValue = TRUE;
            if (ulMValue > MAX_USERS_SHARED)
                bHelp = TRUE;
        }

        else if (strcmp(argv[i], "-nex") == 0) {
            bNextractable = TRUE;
            i--;
        }

        else if (strcmp(argv[i], "-attest") == 0) {
            attest = TRUE;
            i--;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            bTimeout = TRUE;
            ulRet = n3fips_str_to_uint32(&ulTimeoutValue, argv[i + 1]);
            if (ulRet != 0) {
                printf
                    ("\n\tError: Not able to decode core -timeout argument.\n");
                bHelp = TRUE;
            }
        }

        else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                 && (argc > i + 1)) {
            bMinServers = TRUE;
            ulRet = n3fips_str_to_uint8(&ucMinServers, argv[i + 1]);
            if (ulRet != 0) {
                printf
                    ("\n\tError: Not able to decode core -min_srv argument.\n");
                bHelp = TRUE;
            }
            if (ucMinServers > MAX_CLUSTER_SIZE) {
                printf("\n\tError: Invalid value for -min_srv.\n");
                bHelp = TRUE;
            }
        }

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bMod) {
        printf("\n\tError: Modulus size (-m) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }

    if ((ulRet = Cfm2GetPartitionInfo(session_handle,
                                      (Uint8 *) partition_name,
                                      strlen(partition_name),
                                      &partn_info)) != 0) {
        printf("\n\tCfm3GetPartitionInfo returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        goto exit_error;
    }

    if (!bHelp && bMod) {
        fips_state = (partn_info.FipsState);
        if (fips_state == 0) {
            if (ulModLen != 1024 && ulModLen != 2048 && ulModLen != 3072) {
                printf("Incorrect Modulus Length for NON-FIPS mode\n");
                bHelp = TRUE;
            }
        } else {
            if (ulModLen != 2048 && ulModLen != 3072) {
                printf("Incorrect Modulus Length for FIPS mode\n");
                bHelp = TRUE;
            }
        }
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if ((STORAGE_RAM == ucKeyLocation) && bUsers) {
        printf("\n\tError: sharing session keys is not allowed\n");
        bHelp = TRUE;
    }


    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nGenerate DSA key pair specifying modulus length and key label.");
        printf("\n");
        printf
            ("\nSyntax: genDSAKeyPair -h -m <modulus length> -l <label>\n");
        printf("\t\t\t [-sess] [-nex] [-id <key ID>]\n");
        printf("\t\t\t [-u <user-ids>] [-m_value <0..8>] [-attest]\n");
        printf
            ("\t\t\t [-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h        displays this information");
        printf("\n       -m        specifies the modulus length in bits:");
        printf("\n                 Should be either 1024, 2048 or 3072");
        printf("\n       -l        specifies the key label");
        printf("\n       -sess     specifies key as session key");
        printf("\n       -id       specifies key ID");
        printf("\n       -nex      set the key as non-extractable");
        printf
            ("\n       -u        specifies the list of users to share with (separated by ,) (optional)");
        printf
            ("\n       -m_value  specifies the number of users to approve for any key service");
        printf
            ("\n       -attest   performs the attestation check on the firmware response");
        printf
            ("\n       -min_srv  specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                 (till the time specified by -timeout option)");
        printf
            ("\n                 if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout  specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                 If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }
    if (attest) {
        attest_info = CALLOC_WITH_CHECK(sizeof(*attest_info), 1);

        if (!attest_info) {
            printf("couldn't allocate attest info\n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto error;
        }
    }
    ulRet = Cfm3GenerateKeyPair(session_handle,
                                KEY_TYPE_DSA,
                                ulModLen, 0, 0,
                                (Uint16 *) pUsers, ulCount, ulMValue,
                                (Uint8 *) pID, ulIDLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                ucKeyLocation, !bNextractable,
                                (Uint64 *) & ulDSAPublicKey,
                                (Uint64 *) & ulDSAPrivateKey,
                                attest_info, &request_id);
  error:
    printf("\n\tCfm3GenerateKeyPair: returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf
            ("\n\tCfm3GenerateKeyPair:    public key handle: %llu    private key handle: %llu\n",
             (Uint64) ulDSAPublicKey, (Uint64) ulDSAPrivateKey);
        if (attest) {
            verifyAttestation(session_handle, (Uint8 *) attest_info,
                              sizeof(*attest_info));
        }
    }
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if ((success_count >= ucMinServers
                 && success_count2 >= ucMinServers)
                || ((ulTimeoutValue != 0)
                    && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking private key status (%d seconds)..\n",
                   time_taken);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulDSAPrivateKey,
                                  &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
            printf("\n\tChecking public key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulDSAPublicKey,
                                  &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count2);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle,
                                  ulDSAPublicKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
            ulRet = Cfm3DeleteKey(session_handle,
                                  ulDSAPrivateKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);

        } else
            printf
                ("\n\tCfm3GenerateKeyPair:    public key handle: %llu    private key handle: %llu\n",
                 (Uint64) ulDSAPublicKey, (Uint64) ulDSAPrivateKey);
    }

  exit_error:
    if (attest_info)
        free(attest_info);
    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);

    return ulRet;
}

Uint32 sign(int argc, char **argv)
{
    int ret = 0;
    Uint32 ulRet = ERR_INVALID_USER_INPUT;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bPrivateKey = FALSE;
    Uint64 ulPrivateKey = 0;

    Uint8 bMech = FALSE;
    Uint32 ulMech = 0;

    Uint8 bMsg = FALSE;
    Uint8 *pMsg = NULL;
    Uint32 ulMsgLen = 0;

    Uint8 bSig = FALSE;
    char *pSigFile = NULL;

    Uint32 ulSigLen = 512;
    Uint32 ulAttrLen = 0;
#ifndef _WIN32
    Uint8 pSig[512] = { };
    Uint8 pAttr[4]  = { };
#else
    Uint8 pSig[512] = { 0 };
    Uint8 pAttr[4]  = { 0 };
#endif

    HashType hash_type = UNSUPPORTED_HASH;
    PaddingType padding_type = UNKNOWN_PADDING;
    KeyType key_type = KEY_TYPE_ANY;
    Uint16 hash_length = 0;

    Uint8 pDigest[512] = { 0 };
    unsigned char *der_sig = NULL;

    uint32_t curveID = 0;
    uint32_t modulus_size = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        // Key handle
        else if ((!bPrivateKey) && (strcmp(argv[i], "-k") == 0)
                && (argc > i + 1))
            bPrivateKey =
                readIntegerArg(argv[i + 1], (Uint32 *) & ulPrivateKey);
        // Mechanism
        else if ((!bMech) && (strcmp(argv[i], "-m") == 0)
                && (argc > i + 1)) {
            bMech = readIntegerArg(argv[i + 1], (Uint32 *) & ulMech);
            ulMech = get_sign_mechanism(ulMech);
        }
        // Msg
        else if ((!bMsg) && (strcmp(argv[i], "-f") == 0)
                && (argc > i + 1)) {
            bMsg = readFileArg(argv[i + 1], (char **) &pMsg, &ulMsgLen);
            if (!bMsg)
                bHelp = TRUE;

        } else if ((!bSig) && (strcmp(argv[i], "-out") == 0) &&
                (argc > i + 1)) {
            pSigFile = argv[i + 1];
            bSig = 1;

        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bMsg) {
        printf("\n\tError: Message file (-f) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bPrivateKey) {
        printf("\n\tError: Private Key (-k) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bMech) {
        printf("\n\tError: Mechanism (-m) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bSig) {
        printf("\n\tError: Signature File (-out) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nGenerates signature on the given data with given Private Key");
        printf("\n");
        printf
            ("\nSyntax: sign -h -f <msg file> -k <key handle> -m <signature mechanism> -out <signature file>\n");
        printf("\n");
        printf("\nWhere: -h   displays this information");
        printf("\n       -f   Message File");
        printf("\n       -k   Private key handle");
        printf("\n       -m   Signature Mechanism");
        printf("\n             SHA1_RSA_PKCS       - 0");
        printf("\n             SHA256_RSA_PKCS     - 1");
        printf("\n             SHA384_RSA_PKCS     - 2");
        printf("\n             SHA512_RSA_PKCS     - 3");
        printf("\n             SHA224_RSA_PKCS     - 4");
        printf("\n             SHA1_RSA_PKCS_PSS   - 5");
        printf("\n             SHA256_RSA_PKCS_PSS - 6");
        printf("\n             SHA384_RSA_PKCS_PSS - 7");
        printf("\n             SHA512_RSA_PKCS_PSS - 8");
        printf("\n             SHA224_RSA_PKCS_PSS - 9");
        printf("\n             ECDSA_SHA1          - 15");
        printf("\n             ECDSA_SHA224        - 16");
        printf("\n             ECDSA_SHA256        - 17");
        printf("\n             ECDSA_SHA384        - 18");
        printf("\n             ECDSA_SHA512        - 19");
        printf("\n       -out file name to write the signature");
        printf("\n");
        goto exit_out;
    }

    ulAttrLen = sizeof(pAttr);
    ulRet = Cfm3GetAttribute(session_handle,
                             ulPrivateKey,
                             OBJ_ATTR_KEY_TYPE, pAttr, &ulAttrLen,
                             NULL, NULL, NULL);
    if (ulRet) {
        printf
            ("Cfm3GetAttribute to get key type failed %d : %s \n",
             ulRet, Cfm2ResultAsString(ulRet));
        goto exit;
    }

    key_type = atoi((Int8 *) pAttr);

    ulRet = get_hash_info(ulMech, &hash_type, &hash_length, &padding_type,
            key_type);
    if (ulRet != 0) {
        printf
            ("\n\tUnsupported hash type/provided key not valid for signature mechanism\n");
        ulRet = ERR_INVALID_USER_INPUT;
        goto exit;
    }

    ulRet = Cfm2Hash(session_handle, OP_BLOCKING,
            hash_type, ulMsgLen, pMsg, pDigest, NULL);
    if (ulRet != 0) {
        printf("\n\tCfm3Hash returned: 0x%02x %s%s\n",
                ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        goto exit;
    }

    if (key_type == KEY_TYPE_RSA) {
        /* get modulus length from private key */
        ulRet = Cfm3GetAttribute(session_handle,
                ulPrivateKey, OBJ_ATTR_MODULUS, NULL,
                &modulus_size, NULL, NULL, NULL);
        if (ulRet != 0) {
            printf("\n\tFailed to get modulus length\n");
            goto exit;
        }
    }

    if ( (key_type == KEY_TYPE_RSA) && (is_RSA_PKCS(ulMech))) {
        Uint32 outlen = 0;
        outlen = modulus_size;
        der_sig = (unsigned char *) n3fips_calloc(modulus_size + 1);
        if (!der_sig) {
            print_error("\n\tFailed to allocate memory \n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto exit;
        }

        ret = get_x509_digest(hash_type, hash_length, pDigest, der_sig,
                &outlen, modulus_size);
        if (ret) {
            printf("\n\tFailed to convert hash\n");
            free(der_sig);
            ulRet = RET_ERROR;
            goto exit;
        }

        memset(pDigest, 0, 512);
        ret = n3fips_memcpy((char *)pDigest, (char *)der_sig, 512, outlen);
        if (ret) {
            printf("\n\tFailed to copy hash\n");
            free(der_sig);
            ulRet = RET_ERROR;
            goto exit;
        }
        free(der_sig);
        hash_length = outlen;

    }

    if (key_type == KEY_TYPE_RSA) {

        if (padding_type == PSS_PADDING) {
            ulRet = Cfm2Pkcs1v22Sign(session_handle, OP_BLOCKING, ulPrivateKey,
                    PSS, hash_type, 1, modulus_size, hash_length, pDigest,
                    pSig, NULL);
        } else {
            ulRet = Cfm2Pkcs1v15CrtEnc(session_handle, OP_BLOCKING,
                    ulPrivateKey, BT1, modulus_size, hash_length, pDigest,
                    pSig, NULL);
        }
        if (ulRet != 0) {
            goto exit;
        }
        ulSigLen = modulus_size;
    } else {
        int cid = -1;
        Uint32 prime_length;
        int signLen = -1;
        ECDSA_SIG *sig = NULL;
        Uint32 size = sizeof(curveID);

        Uint8 k[MAX_HASH_LENGTH] = { 0 }, s[MAX_HASH_LENGTH] = { 0 },
              r[MAX_HASH_LENGTH] = { 0 };

        ulRet = Cfm3GetAttribute(session_handle,
                ulPrivateKey, OBJ_ATTR_MODULUS_BITS, (Uint8*)&curveID,
                &size, NULL, NULL, NULL);
        if (ret != 0) {
            printf("\n\tCfm3GetAttribute returned: 0x%02x %s%s\n",
                ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            goto exit;
        }

        curveID = atoi((char *) &curveID);

        /* get the curve ID from the NID curve ID */
        cid = get_curve_id_from_NID(curveID);
        if (cid != P256  && cid != P384 && cid != Secp256k1) {
            printf("\n\tUnsupported curve ID. Supported curves: P256, P384, Secp256k1\n");
            ulRet = ERR_UNSUPPORTED_CURVE;
            goto exit;
        }

        prime_length = get_prime_length(cid);
        signLen = 2 * prime_length + DER_ENCODED_ECC_SIG_HDR_LEN;

        sig = ECDSA_SIG_new();
        if (!sig) {
            printf("\n\tECDSA_SIG_new failed\n");
            ulRet = RET_ERROR;
            goto exit;
        }

        ulRet = Cfm2ECDSASign(session_handle, OP_BLOCKING, cid,
                ulPrivateKey,
                k, prime_length,
                pDigest, hash_length, r, s, NULL);
        if (ulRet) {
            ECDSA_SIG_free(sig);
            goto exit;
        }

        /* converting r and s values from BIN to BN */
        BN_bin2bn(r, prime_length, sig->r);
        BN_bin2bn(s, prime_length, sig->s);

        ret = i2d_ECDSA_SIG(sig, &der_sig);
        if (ret == 0) {
            printf("\n\tSign convertion failed\n");
            ECDSA_SIG_free(sig);
            ulRet = RET_ERROR;
            goto exit;
        }

        ECDSA_SIG_free(sig);

        ret = n3fips_memcpy((char *)pSig, (char *)der_sig, 512, signLen);
        if (ret) {
            printf("\n\tFailed to copy sign\n");
            ulRet = RET_ERROR;
            goto exit;
        }
        ulSigLen = signLen;
    }

    if (ulRet == 0) {
        printf("\n\tSignature creation successful\n");
        ulRet = write_file(pSigFile, pSig, ulSigLen);
        printf("\n\tsignature is written to file %s\n", pSigFile);
    }

exit:
    printf("\n\tCfm3Sign: sign returned: 0x%02x %s%s\n",
                 ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
exit_out:
    return ulRet;
}


static Uint32 getECPointFromPublicKey(Uint64 kh, Uint8 *px, Uint32 *px_len,
        Uint8 *py, Uint32 *py_len, int *cid)
{
    EC_GROUP *group = NULL;
    EC_POINT *pub = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *pub_x = NULL, *pub_y = NULL;
    int xlen, ylen;
    Uint32 curveID = 0;
    Uint32 size = 0;
    Uint32 ret = 0;

#define MAX_EX_ECCKEY_LEN 1024
    uint8_t pub_point[MAX_EX_ECCKEY_LEN] = { 0 };
    uint32_t pointKeyLen = MAX_EX_ECCKEY_LEN;


    if ( !px || !px_len || !py || !py_len || !cid) {
        ret = ERR_INVALID_INPUT;
        goto end;
    }

    size = sizeof(curveID);
    ret = Cfm3GetAttribute(session_handle,
            kh, OBJ_ATTR_MODULUS_BITS, (Uint8*)&curveID,
            &size, NULL, NULL, NULL);
    if (ret != 0) {
        printf("\n\tCfm3GetAttribute returned: 0x%02x \n\n\t%s\n",
                ret, Cfm2ResultAsString(ret));
        goto end;
    }

    curveID = atoi((char *) &curveID);

    *cid = get_curve_id_from_NID(curveID);
    if (*cid != P256  && *cid != P384 && *cid != Secp256k1) {
        printf("\n\tUnsupported curve ID. Supported curves: P256, P384, Secp256k1\n");
        ret = ERR_UNSUPPORTED_CURVE;
        goto end;
    }

    ret = Cfm2ExportPublicKey2(session_handle,
            kh,
            pub_point, &pointKeyLen, NULL);
    if (ret) {
        printf("\n\tCfm3ExportPublicKey returned: 0x%02x \n\n\t%s\n",
               ret, Cfm2ResultAsString(ret));
        goto end;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        ret = ERR_GENERAL_ERROR;
        goto end;
    }

    BN_CTX_start(ctx);
    pub_x = BN_CTX_get(ctx);
    if (pub_x == NULL) {
        ret = ERR_MEMORY_ALLOC_FAILURE;
        goto end;
    }
    pub_y = BN_CTX_get(ctx);
    if (pub_y == NULL) {
        ret = ERR_MEMORY_ALLOC_FAILURE;
        goto end;
    }
    group = EC_GROUP_new_by_curve_name(curveID);
    if (group == NULL) {
        ret = ERR_MEMORY_ALLOC_FAILURE;
        goto end;
    }

    pub = EC_POINT_new(group);
    if (pub == NULL) {
        ret = ERR_MEMORY_ALLOC_FAILURE;
        goto end;
    }

    if (!EC_POINT_oct2point
            (group, pub, (unsigned char *) pub_point, pointKeyLen, ctx)) {
        printf("\n\tFailed to get the point \n");
        ret = ERR_GENERAL_ERROR;
        goto end;
    }

    if (!EC_POINT_get_affine_coordinates_GFp
            (group, pub, pub_x, pub_y, ctx)) {
        ret = ERR_GENERAL_ERROR;
        goto end;
    }

    xlen = BN_num_bytes(pub_x);
    ylen = BN_num_bytes(pub_y);

    if (xlen > *px_len || ylen > *py_len) {
        ret = ERR_INVALID_INPUT;
        goto end;
    }

    BN_bn2bin(pub_x, px);
    BN_bn2bin(pub_y, py);

    *px_len = xlen;
    *py_len = ylen;

end:
    if (pub)
        EC_POINT_free(pub);
    if (group)
        EC_GROUP_free(group);
    if (pub_x)
        BN_free(pub_x);
    if (pub_y)
        BN_free(pub_y);
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}


static int verify_x509_sig(Uint8 * decSig, Uint32 outlen, Uint8 * pDigest,
                    Uint32 ulDigestLen)
{
    const unsigned char *p = decSig;
    X509_SIG *tx509 = NULL;
    int ret = 0;

    tx509 = d2i_X509_SIG(NULL, &p, outlen);

    if (NULL == tx509) {
        print_error("\n\tFailed to convert DER key\n");
        return -1;
    }

    if (memcmp(pDigest, tx509->digest->data, ulDigestLen)) {
        ret = -1;
        goto end;
    }

end:
    if (tx509)
        X509_SIG_free(tx509);
    return ret;
}



Uint32 verify(int argc, char **argv)
{
    Uint32 ulRet = ERR_INVALID_USER_INPUT;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bMech = FALSE;
    Uint32 ulMech = 0;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bMsg = FALSE;
    Uint8 *pMsg = NULL;
    Uint32 ulMsgLen = 0;

    Uint8 bSig = FALSE;
    char *pSig = NULL;
    Uint32 ulSigLen = 0;
    Uint16 ulResultLen = 0;
    Uint32 ulAttrLen = 0;

#ifndef _WIN32
    Uint8 pResult[512] = { };
    Uint8 pAttr[4]     = { };
#else
    Uint8 pResult[512] = { 0 };
    Uint8 pAttr[4]     = { 0 };
#endif

    HashType hash_type = UNSUPPORTED_HASH;
    PaddingType padding_type = UNKNOWN_PADDING;
    KeyType key_type = KEY_TYPE_ANY;
    Uint16 hash_length = 0;

    ECDSA_SIG *sig = NULL;

    Uint8 pDigest[512] = { 0 };
    const unsigned char *der_sig = NULL;

    uint32_t modulus_size = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // Key handle
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKey = readIntegerArg(argv[i + 1], (Uint32 *) & ulKey);

        // Mechanism
        else if ((!bMech) && (strcmp(argv[i], "-m") == 0)
                 && (argc > i + 1)) {
            bMech = readIntegerArg(argv[i + 1], (Uint32 *) & ulMech);
            ulMech = get_sign_mechanism(ulMech);
        }
        // Msg
        else if ((!bMsg) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1))
            bMsg = readFileArg(argv[i + 1], (char **) &pMsg, &ulMsgLen);

        // Sig
        else if ((!bSig) && (strcmp(argv[i], "-s") == 0)
                 && (argc > i + 1))
            bSig = readFileArg(argv[i + 1], &pSig, &ulSigLen);
        /* Any file data read will be freed at the end of the command
         * as part of clearAndResetDynamicBufferVector */

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bMsg) {
        printf("\n\tError: Message file (-f) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bSig) {
        printf("\n\tError: Signature file (-s) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bKey) {
        printf("\n\tError: Private Key (-k) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bMech) {
        printf("\n\tError: Mechanism (-m) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nVerifies signature on the given data with give Public Key");
        printf("\n");
        printf("\nSyntax: verify -h -f <msg file> "
               "-s <signature file> -k <key handle> -m <verify mechanism>\n");
        printf("\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -f  Message File");
        printf("\n       -s  Signature File");
        printf("\n       -k  Public key handle");
        printf("\n       -m  Verification Mechanism");
        printf("\n            SHA1_RSA_PKCS       - 0");
        printf("\n            SHA256_RSA_PKCS     - 1");
        printf("\n            SHA384_RSA_PKCS     - 2");
        printf("\n            SHA512_RSA_PKCS     - 3");
        printf("\n            SHA224_RSA_PKCS     - 4");
        printf("\n            SHA1_RSA_PKCS_PSS   - 5");
        printf("\n            SHA256_RSA_PKCS_PSS - 6");
        printf("\n            SHA384_RSA_PKCS_PSS - 7");
        printf("\n            SHA512_RSA_PKCS_PSS - 8");
        printf("\n            SHA224_RSA_PKCS_PSS - 9");
        printf("\n            ECDSA_SHA1          - 15");
        printf("\n            ECDSA_SHA224        - 16");
        printf("\n            ECDSA_SHA256        - 17");
        printf("\n            ECDSA_SHA384        - 18");
        printf("\n            ECDSA_SHA512        - 19");
        printf("\n");
        goto exit_out;
    }

    ulAttrLen = sizeof(pAttr);
    ulRet = Cfm3GetAttribute(session_handle,
                             ulKey,
                             OBJ_ATTR_KEY_TYPE, pAttr, &ulAttrLen,
                             NULL, NULL, NULL);
    if (ulRet) {
        printf
            ("Cfm3GetAttribute to get key type failed %d : %s \n",
             ulRet, Cfm2ResultAsString(ulRet));
        goto exit;
    }

    key_type = atoi((Int8 *) pAttr);

    ulRet = get_hash_info(ulMech, &hash_type, &hash_length, &padding_type,
            key_type);
    if (ulRet != 0) {
        printf
            ("\n\tUnsupported hash type/provided key not valid for verification mechanism\n");
        ulRet = ERR_INVALID_USER_INPUT;
        goto exit;
    }

    ulRet = Cfm2Hash(session_handle, OP_BLOCKING,
            hash_type, ulMsgLen, pMsg, pDigest, NULL);
    if (ulRet != 0) {
        printf("\n\tCfm3Hash returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        goto exit;
    }

    if (key_type == KEY_TYPE_RSA) {

        ulRet = Cfm3GetAttribute(session_handle,
                ulKey, OBJ_ATTR_MODULUS, NULL,
                &modulus_size, NULL, NULL, NULL);
        if (ulRet != 0) {
            printf("\n\tCfm3GetAttribute returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            goto exit;
        }

        if (ulSigLen != modulus_size) {
            ulRet = RET_INVALID_INPUT;
            printf("\n\tInvalid signature length\n");
            goto exit;
        }

        if (padding_type == PSS_PADDING) {
            ulRet = Cfm2Pkcs1v22Verify(session_handle, OP_BLOCKING, ulKey,
                    PSS, hash_type, modulus_size, hash_length, pDigest,
                    (Uint8*)pSig, pResult, NULL);
            if (ulRet != 0) {
                goto exit;
            }
        } else {
            ulRet = Cfm2Pkcs1v15Dec(session_handle, OP_BLOCKING,
                    ulKey, BT1, modulus_size, (Uint8*)pSig,
                    (Uint8*) pResult, RESULT_PTR, &ulResultLen, NULL);
            if (ulRet != 0) {
                goto exit;
            }
            if (verify_x509_sig(pResult, ulResultLen, pDigest, hash_length)) {
                printf("\n\tFailed to verify signature\n");
                ulRet = ERR_INVALID_INPUT;
                goto exit;
            }
        }
    } else {
        int cid = -1;
        Uint32 px_len = 0, py_len = 0;
        Uint8 pub_x[512], pub_y[512];
        Uint32 prime_length = 0;
        Uint8 s[MAX_HASH_LENGTH] = { 0 },
              r[MAX_HASH_LENGTH] = { 0 };

        px_len = sizeof(pub_x);
        py_len = sizeof(pub_y);

        memset(pub_x, 0, sizeof(pub_x));
        memset(pub_y, 0, sizeof(pub_y));

        ulRet = getECPointFromPublicKey(ulKey, pub_x, &px_len, pub_y,
                &py_len, &cid);
        if (ulRet) {
            printf("\n\tFailed to do ECDSA verify \n");
            goto exit;
        }

        if (cid != P256  && cid != P384 && cid != Secp256k1) {
            printf("\n\tUnsupported curve ID. Supported curves: P256, P384, Secp256k1\n");
            ulRet = RET_INVALID_INPUT;
            goto exit;
        }

        /* decoding the key received in the buffer */
        der_sig = (const unsigned char*) pSig;
        sig = d2i_ECDSA_SIG(NULL, &der_sig, ulSigLen);
        if (NULL == sig) {
            printf("\n\tInvalid signature\n");
            ulRet = ERR_INVALID_INPUT;
            goto exit;
        }

        prime_length = get_prime_length(cid);

        if (convert_bn_to_bin(sig->r, r, prime_length)) {
            printf("\n\tInvalid signature\n");
            ulRet = ERR_INVALID_INPUT;
            goto exit;
        }

        if (convert_bn_to_bin(sig->s, s, prime_length)) {
            printf("\n\tInvalid signature\n");
            ulRet = ERR_INVALID_INPUT;
            goto exit;
        }

        ulRet = Cfm2ECDSAVerify(session_handle, OP_BLOCKING, cid,
                pub_x, pub_y, pDigest, hash_length, r, s, NULL);
        if (ulRet) {
            goto exit;
        }
    }

    printf("\n\tSignature verifition successful\n");
  exit:
    printf("\n\tCfm3Verify returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
exit_out:
    if (sig)
        ECDSA_SIG_free(sig);
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : listECCCurveIds
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 listECCCurveIds(int argc, char **argv)
{
    printf("\n");
    printf("\nDescription");
    printf("\n===========");
    printf("\nThe following are HSM supported ECC CurveIds");
    printf("\n");
    printf("\n      NID_X9_62_prime192v1            = %d", 0x00000001);
    printf("\n      NID_X9_62_prime256v1            = %d", 0x00000002);
    printf("\n      NID_sect163k1                   = %d", 0x00000003);
    printf("\n      NID_sect163r2                   = %d", 0x00000004);
    printf("\n      NID_sect233k1                   = %d", 0x00000005);
    printf("\n      NID_sect233r1                   = %d", 0x00000006);
    printf("\n      NID_sect283k1                   = %d", 0x00000007);
    printf("\n      NID_sect283r1                   = %d", 0x00000008);
    printf("\n      NID_sect409k1                   = %d", 0x00000009);
    printf("\n      NID_sect409r1                   = %d", 0x0000000A);
    printf("\n      NID_sect571k1                   = %d", 0x0000000B);
    printf("\n      NID_sect571r1                   = %d", 0x0000000C);
    printf("\n      NID_secp224r1                   = %d", 0x0000000D);
    printf("\n      NID_secp384r1                   = %d", 0x0000000E);
    printf("\n      NID_secp521r1                   = %d", 0x0000000F);
    printf("\n      NID_secp256k1                   = %d", 0x00000010);
    printf("\n\n");
    return 0;
}

/****************************************************************************
 *
 * FUNCTION     : aesWrapUnwrap
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 aesWrapUnwrap(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;

    Uint8 bWrappingKey = FALSE;
    Uint64 ulWrappingKey = 0;

    Uint8 bMode = FALSE;
    Uint32 ulMode = 0;

    Uint8 bIV = FALSE;
    Uint64 default_iv = 0;
    Uint8 *pIV = NULL;

    Uint8 *pResultData = NULL;
    Uint32 ulResultLen = 0;

    Uint8 *pInputKey = NULL;
    Uint32 ulInputKeyLen = 0;

    Uint8 bFile = FALSE;
    char *key_file = NULL;
    Uint32 ulTemp = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // file to be wrapped or unwrapped
        else if ((!bKey) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1))
            bKey = readFileArg(argv[i + 1], (char **) &pInputKey,
			       &ulInputKeyLen);
        // output file to write the wrapped or unwrapped data
        else if ((!bFile) && (strcmp(argv[i], "-out") == 0)
                 && (argc > i + 1)) {
            key_file = argv[i + 1];
            bFile = 1;
        }
        // wrapping key
        else if ((!bWrappingKey) && (strcmp(argv[i], "-w") == 0)
                 && (argc > i + 1)) {
            bWrappingKey = readIntegerArg(argv[i + 1], &ulTemp);
            ulWrappingKey = ulTemp;
        }
        // wrapping iv
        else if ((!bIV) && (strcmp(argv[i], "-i") == 0)
                 && (argc > i + 1)) {
            Uint32 ulIVLen = 0;
            BIGNUM *n = NULL;
            bIV = readArgAsString(argv[i + 1], (char **) &pIV, &ulIVLen);
            n = BN_new();
            BN_hex2bn(&n, (char *) pIV);
            ulIVLen = BN_num_bytes(n);
            BN_bn2bin(n, pIV);
            BN_free(n);
            if (ulIVLen != 8) {
                printf("\nError: Invalid IV length %d\n", ulIVLen);
                bHelp = TRUE;
            }
        }
        // wrapping/unwrapping mode
        else if ((!bMode) && (strcmp(argv[i], "-m") == 0)
                 && (argc > i + 1)) {
            if (readIntegerArg(argv[i + 1], &ulMode)) {
                if (ulMode == 0 || ulMode == 1)
                    bMode = TRUE;
                else {
                    printf
                        ("\n\tError: wrapping or unwrapping mode should be 0 or 1.\n");
                    bHelp = TRUE;
                }
            } else {
                printf
                    ("\n\tError: wrapping or unwrapping mode should be 0 or 1.\n");
                bHelp = TRUE;
            }
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf
            ("\n\tError: file to be wrapped/unwrapped (-f) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bWrappingKey) {
        printf("\n\tError: Handle of wrapping Key (-w) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bIV) {
        printf("\n\tWarning: IV (-i) is missing.\n");
        printf("\t\t 0xA6A6A6A6A6A6A6A6 is considered as default IV\n");
        pIV = (Uint8 *) & default_iv;
    }
    if (!bHelp && !bMode) {
        printf
            ("\n\tError: wrapping or unwrapping mode (-m) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nWraps/Unwraps data with specified AES key.");
        printf("\n");
        printf
            ("\nSyntax: aesWrapUnwrap -h -f <file to wrap/unwrap> "
             "-w <wrapping/unwrapping key handle> -m <wrap/unwrap mode> "
             "\n\t\t      [-i <wrapping IV>] [-out <file to write the wrapped/unwrapped data out>]\n");
        printf("\n");
        printf("\nWhere: -h    displays this information");
        printf
            ("\n       -w    specifies the handle of the AES wrapping/unwrapping key");
        printf
            ("\n       -f    file to be wrapped or unwrapped (Supported file size is <= 4K bytes)");
        printf("\n       -m    specifies the mode:");
        printf("\n              wrap - 1");
        printf("\n              unwrap - 0");
        printf("\n       -i    specifies the IV to be used (optional)");
        printf
            ("\n       -out  file to write the wrapped or unwrapped data out (optional)");
        printf("\n");
        goto exit_out;
    }

    if (ulMode) {
        ulRet = Cfm3WrapHostKey(session_handle,
                                pInputKey,
                                ulInputKeyLen,
                                ulWrappingKey, pIV,
                                NULL, &ulResultLen, NULL);
        if (ERR_BUFFER_TOO_SMALL == ulRet) {
            pResultData = CALLOC_WITH_CHECK(1, ulResultLen);
            if (NULL == pResultData) {
                ulRet = ERR_MEMORY_ALLOC_FAILURE;
                printf("Memory allocation failure\n");
                goto exit;
            }
            ulRet = Cfm3WrapHostKey(session_handle,
                                    pInputKey,
                                    ulInputKeyLen,
                                    ulWrappingKey, pIV,
                                    pResultData, &ulResultLen, NULL);
        }
    } else {
       ulRet = Cfm3UnWrapHostKey(session_handle,
                                 pInputKey,
                                 ulInputKeyLen,
                                 NULL,
                                 &ulResultLen, ulWrappingKey, pIV, NULL);
       if (ERR_BUFFER_TOO_SMALL == ulRet) {
            pResultData = CALLOC_WITH_CHECK(1, ulResultLen);
            if (NULL == pResultData) {
                ulRet = ERR_MEMORY_ALLOC_FAILURE;
                printf("Memory allocation failure\n");
                goto exit;
            }
            ulRet = Cfm3UnWrapHostKey(session_handle,
                                      pInputKey,
                                      ulInputKeyLen,
                                      pResultData,
                                      &ulResultLen, ulWrappingKey, pIV, NULL);
       }
    }

    if (ulRet)
        goto exit;

    printf("result data:");
    for (i = 0; i < ulResultLen; i++) {
        if ((i % 8) == 0)
            printf("\n");
        printf("%02X ", (Uint8) pResultData[i]);
    }

    if (!bFile)
        key_file = (ulMode) ? "wrapped_key" : "unwrapped_key";

    // write to a file
    if (WriteBinaryFile(key_file, (char *) pResultData, ulResultLen))
        printf("\n\nresult written to file %s \n", key_file);
    else {
        ulRet = ERR_WRITE_OUTPUT_FILE;
        printf("\n\nFailed to write result into a file.\n");
    }

exit:
    printf("\n\t%s returned: 0x%02x %s%s\n",
           (ulMode ? ("Cfm3WrapHostKey") : ("Cfm3UnWrapHostKey")),
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
exit_out:
    if (pIV && bIV)
        free(pIV);
    if (pResultData)
        free(pResultData);
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : aesUnwrapPkcs8Buffer
 *
 * DESCRIPTION  : Unwraps data (old blob wrapped using fw version < 2.04)
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 aesUnwrapPkcs8Buffer(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;

    Uint8 bWrappingKey = FALSE;
    Uint64 ulWrappingKey = 0;

    Uint8 bIV = FALSE;
    Uint64 default_iv = 0;
    Uint8 *pIV = NULL;

    Uint8 *pResultData = NULL;
    Uint32 ulResultLen = 0;

    Uint8 *pInputKey = NULL;
    Uint32 ulInputKeyLen = 0;

    Uint8 bFile = FALSE;
    char *key_file = NULL;
    Uint32 ulMech = CRYPTO_MECH_AES_KEY_WRAP_NO_PAD;
    Uint32 ulMode = 0; //unWrap

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // file to be wrapped or unwrapped
        else if ((!bKey) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1))
            bKey = readFileArg(argv[i + 1], (char **) &pInputKey,
                               &ulInputKeyLen);
        // output file to write the wrapped or unwrapped data
        else if ((!bFile) && (strcmp(argv[i], "-out") == 0)
                 && (argc > i + 1)) {
            key_file = argv[i + 1];
            bFile = 1;
        }
        // wrapping key
        else if ((!bWrappingKey) && (strcmp(argv[i], "-w") == 0)
                 && (argc > i + 1)) {
            bWrappingKey = readLongIntegerArg(argv[i + 1], &ulWrappingKey);
        }
        // wrapping iv
        else if ((!bIV) && (strcmp(argv[i], "-i") == 0)
                 && (argc > i + 1)) {
            Uint32 ulIVLen = 0;
            BIGNUM *n = NULL;
            bIV = readArgAsString(argv[i + 1], (char **) &pIV, &ulIVLen);
            n = BN_new();
            BN_hex2bn(&n, (char *) pIV);
            ulIVLen = BN_num_bytes(n);
            BN_bn2bin(n, pIV);
            BN_free(n);
            if (ulIVLen != 8) {
                printf("\nError: Invalid IV length %d\n", ulIVLen);
                bHelp = TRUE;
            }
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf
            ("\n\tError: file to be unwrapped (-f) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bWrappingKey) {
        printf("\n\tError: Handle of unwrapping Key (-w) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bIV) {
        printf("\n\tWarning: IV (-i) is missing.\n");
        printf("\t\t 0xA6A6A6A6A6A6A6A6 is considered as default IV\n");
        pIV = (Uint8 *) & default_iv;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nUnwraps data(old blob wrapped using fw version < 2.04) with specified AES key.");
        printf("\n");
        printf
            ("\nSyntax: aesUnwrapPkcs8Buffer -h -f <file to unwrap> -w <unwrapping key handle>"
             "\n\t\t      [-i <wrapping IV>] [-out <file to write the unwrapped data out>]\n");
        printf("\n");
        printf("\nWhere: -h    displays this information");
        printf("\n       -w    specifies the handle of the AES unwrapping key");
        printf("\n       -f    file to be unwrapped (Supported file size is < 4K bytes)");
        printf("\n       -i    specifies the IV to be used (optional)");
        printf("\n       -out  file to write the unwrapped data out (optional)");
        printf("\n");
        goto exit_out;
    }

    ulRet = Cfm2AesWrapUnwrapBuffer4(session_handle,
                                     ulWrappingKey,
                                     pInputKey,
                                     ulInputKeyLen,
                                     *(Uint64 *)pIV,
                                     NULL, &ulResultLen,
                                     ulMode, ulMech, NULL);

    if (ERR_BUFFER_TOO_SMALL == ulRet) {
        pResultData = CALLOC_WITH_CHECK(1, ulResultLen);
        if (NULL == pResultData) {
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            printf("Memory allocation failure\n");
            goto exit;
        }
        ulRet = Cfm2AesWrapUnwrapBuffer4(session_handle,
                                         ulWrappingKey,
                                         pInputKey,
                                         ulInputKeyLen,
                                         *(Uint64 *)pIV,
                                         pResultData, &ulResultLen,
                                         ulMode, ulMech, NULL);
    }
    if (ulRet)
        goto exit;

    ulRet = verify_and_remove_aes_padding(pResultData, &ulResultLen);
    if (ulRet)
        goto exit;

    printf("result data:");
    for (i = 0; i < ulResultLen; i++) {
        if ((i % 8) == 0)
            printf("\n");
        printf("%02X ", (Uint8) pResultData[i]);
    }

    if (!bFile)
        key_file = "unwrapped_key";

    // write to a file
    if (WriteBinaryFile(key_file, (char *) pResultData, ulResultLen))
        printf("\n\nresult written to file %s \n", key_file);
    else {
        ulRet = ERR_WRITE_OUTPUT_FILE;
        printf("\n\nFailed to write result into a file.\n");
    }

exit:
    printf("\n\t%s returned: 0x%02x %s%s\n",
           "aesUnwrapPkcs8Buffer",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
exit_out:
    if (pIV && bIV)
        free(pIV);
    if (pResultData)
        free(pResultData);
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : genRSAKeyPair
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 genRSAKeyPair(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    int k=0;
    int loop=0;
    Uint64 ulRSAPublicKey = 0;
    Uint64 ulRSAPrivateKey = 0;

    Uint8 bMod = FALSE;
    Uint32 ulModLen = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulCount = 0;

    Uint8 bMValue = FALSE;
    Uint8 ulMValue = 1;


    Uint8 bExp = FALSE;
    Uint32 ulPubExp = 0;

    Uint8 attest = FALSE;
    PartitionInfo partn_info = { {0} };
    Uint32 fips_state = 0;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;

    Uint32 success_count2 = 0;

    KeyGenAttest *attest_info = NULL;

    Uint8 bNextractable = FALSE;
    char *pTemp = NULL;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // exp
        else if ((!bExp) && (strcmp(argv[i], "-e") == 0)
                 && (argc > i + 1))
            bExp = validateReadPublicExponentIntegerArg(argv[i + 1], &ulPubExp);

        // Mod
        else if ((!bMod) && (strcmp(argv[i], "-m") == 0)
                 && (argc > i + 1))
            bMod = readIntegerArg(argv[i + 1], &ulModLen);

        // Label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulCount);
        } else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        } else if (strcmp(argv[i], "-nex") == 0) {
            bNextractable = TRUE;
            i--;
        } else if (strcmp(argv[i], "-attest") == 0) {
            attest = TRUE;
            i--;                //This for loops skips i by 2. so go with it.
        } else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                   && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        } else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                   && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else if ((!bMValue) && (strcmp(argv[i], "-m_value") == 0)
                   && (argc > i + 1)) {
            ulMValue = atoi(argv[i + 1]);
            bMValue = TRUE;
            if (ulMValue > MAX_USERS_SHARED || ulMValue < 1) {
                printf("\n\tError: Invalid m_value.\n");
                printf("\n\tValid m_value range is 1 to %d\n",
                       MAX_USERS_SHARED);
                bHelp = TRUE;
            }
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bMod) {
        printf("\n\tError: Modulus size (-m) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bExp) {
        printf("\n\tError: Public exponant (-e) is missing or invalid input passed\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if ((STORAGE_RAM == ucKeyLocation) && bUsers) {
        printf("\n\tError: sharing session keys is not allowed\n");
        bHelp = TRUE;
    }

    if ((ulRet = Cfm2GetPartitionInfo(session_handle,
                                      (Uint8 *) partition_name,
                                      partition_name ?
                                      strlen(partition_name) : 0,
                                      &partn_info)) != 0) {
        printf("\n\tCfm3GetPartitionInfo returned: 0x%02x %s%s\n", ulRet,
               ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        goto exit_error;
    }

    if (!bHelp && bMod) {
        fips_state = partn_info.FipsState;
        if (fips_state == 0) {
            if (ulModLen < 1024 || ulModLen > 4096 || ulModLen % 256) {
                printf("Incorrect Modulus Length for NON-FIPS mode\n");
                bHelp = TRUE;
            }
        } else {
            if (ulModLen < 2048 || ulModLen > 4096 || ulModLen % 256) {
                printf("Incorrect Modulus Length for FIPS mode\n");
                bHelp = TRUE;
            }
            if (ulModLen == 2048){
                loop=200;
            }else{
                loop=100;
            }
        }
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nGenerate RSA key pair specifying modulus length, public exponent");
        printf("\nand key label.");
        printf("\n");
        printf("\nSyntax: genRSAKeyPair -h -m <modulus length> "
               "-e <public exponent> -l <label>"
               "\n\t\t\t [-sess] [-nex] [-id <key ID>]"
               "\n\t\t\t [-u <user-ids>] [-m_value <0..8>] [-attest]");
        printf
            ("\n\t\t\t [-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h        displays this information");
        printf
            ("\n       -m        specifies the modulus length: eg. 2048");
        printf
            ("\n       -e        specifies the public exponent: any odd number typically >= 65537 to 2^31 - 1");
        printf("\n       -l        specifies the key label");
        printf("\n       -sess     specifies key as session key");
        printf("\n       -id       specifies key ID");
        printf("\n       -nex      set the key as non-extractable");
        printf
            ("\n       -u        specifies the list of users to share with (separated by ,) (optional)");
        printf
            ("\n       -m_value  specifies the number of users to approve for any key service");
        printf
            ("\n       -attest   performs the attestation check on the firmware response");
        printf
            ("\n       -min_srv  specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                 (till the time specified by -timeout option)");
        printf
            ("\n                 if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout  specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                 If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }
    if (attest) {
        attest_info = calloc(sizeof(*attest_info), 1);

        if (!attest_info) {
            printf("couldn't allocate attest info\n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto error;
        }
    }
    for (k=0;k<loop;k++){
    ulRet = Cfm3GenerateKeyPair(session_handle,
                                KEY_TYPE_RSA,
                                ulModLen, ulPubExp, 0,
                                (Uint16 *) pUsers, ulCount, ulMValue,
                                (Uint8 *) pID, ulIDLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                ucKeyLocation, !bNextractable,
                                (Uint64 *) & ulRSAPublicKey,
                                (Uint64 *) & ulRSAPrivateKey,
                                attest_info, &request_id);
    printf("\n\tCfm3GenerateKeyPair returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf
            ("\n\tCfm3GenerateKeyPair:    public key handle: %llu    private key handle: %llu\n",
             (Uint64) ulRSAPublicKey, (Uint64) ulRSAPrivateKey);
        if (attest) {
            verifyAttestation(session_handle, (Uint8 *) attest_info,
                              sizeof(*attest_info));
        }
    }
    }

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }

    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }

    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if ((success_count >= ucMinServers
                 && success_count2 >= ucMinServers)
                || ((ulTimeoutValue != 0)
                    && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking private key status (%d seconds)..\n",
                   time_taken);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulRSAPrivateKey,
                                  &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
            printf("\n\tChecking public key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulRSAPublicKey,
                                  &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count2);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle,
                                  ulRSAPublicKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
            ulRet = Cfm3DeleteKey(session_handle,
                                  ulRSAPrivateKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);

        } else
            printf
                ("\n\tCfm3GenerateKeyPair:    public key handle: %llu    private key handle: %llu\n",
                 (Uint64) ulRSAPublicKey, (Uint64) ulRSAPrivateKey);

    }


  error:
    if (attest_info)
        free(attest_info);

  exit_error:
    if (pTemp)
        free(pTemp);
    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : createPublicKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 createPublicKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint64 ulRSAPublicKey = 0;

    Uint8 bMod = FALSE;
    Uint8 *pModulus = 0;
    Uint32 ulModLen = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;

    Uint8 bExp = FALSE;
    Uint32 ulPubExp = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // exp
        else if ((!bExp) && (strcmp(argv[i], "-e") == 0)
                 && (argc > i + 1))
            bExp = readIntegerArg(argv[i + 1], &ulPubExp);

        // Mod
        else if ((!bMod) && (strcmp(argv[i], "-m") == 0)
                 && (argc > i + 1)) {
            BIGNUM *n = NULL;
            bMod =
                readArgAsString(argv[i + 1], (char **) &pModulus,
                                &ulModLen);
            n = BN_new();
            BN_hex2bn(&n, (char *) pModulus);
            ulModLen = BN_num_bytes(n);
            BN_bn2bin(n, pModulus);
            BN_free(n);
        }
        // Label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        } else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                   && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bMod) {
        printf("\n\tError: Modulus (-m) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bExp) {
        printf("\n\tError: Public exponant (-e) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nCreates RSA public key.");
        printf("\n");
        printf
            ("\nSyntax: createPublicKey -h -m <modulus> -e <exponent> -l <label>\n");
        printf("\t\t\t[-sess] [-id <key ID>]\n");
        printf("\t\t\t[-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf("\n       -m       specifies the modulus in hex format");
        printf
            ("\n                ex: when modulus is extracted using \"openssl rsa -in <key file> -modulus\"");
        printf("\n       -e       specifies the exponent: eg. 3");
        printf("\n       -l       specifies the label");
        printf("\n       -sess    specifies key as session key");
        printf("\n       -id      specifies key ID");
        printf
            ("\n                Note: For more details on the usage of this");
        printf("\n                      command, please refer Cfm3Util example documentation");
        printf
            ("\n       -min_srv specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                (till the time specified by -timeout option)");
        printf
            ("\n                if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }

    ulRet = Cfm3CreatePublicKey(session_handle,
                                KEY_TYPE_RSA,
                                ulModLen,
                                ulPubExp,
                                0,
                                pModulus,
                                ulModLen,
                                NULL, 0,
                                (Uint8 *) pID, ulIDLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                ucKeyLocation,
                                &ulRSAPublicKey, &request_id);

    if (ulRet == 0)
        printf("\n\tPublic Key Created.  Key Handle: %llu\n",
               ulRSAPublicKey);
    printf("\n\tCfm3CreateRSAPublicKey returned: 0x%02x %s%s\n", ulRet,
           ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulRSAPublicKey,
                                  &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle,
                                  ulRSAPublicKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        } else
            printf("\n\tPublic Key Created.  Key Handle: %llu\n",
                   ulRSAPublicKey);
    }

  exit_error:
    if (pModulus)
        free(pModulus);
    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : importPublicKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 importPublicKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint64 ulHandle = 0;

    Uint8 bFile = FALSE;
    char *pFile = 0;
    Uint32 ulFileLen = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;
    Int32 ulKeyType = 0;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;

    FILE *fp = NULL;
    char *keyfile = NULL;

    Uint8 *pKeyData = NULL;
    Uint32 ulKeyDataLen = 0;
    Uint32 ulModLen = 0;
    Uint32 ulPubExp = 0;
    Uint32 ulCurveId = 0;
    const EC_GROUP *group = NULL;
    RSA *rsa = NULL;
    DSA *dsa = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0) {
            bHelp = TRUE;
            break;
        }
        // file
        else if ((!bFile) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1)) {
            bFile = readFileArg(argv[i + 1], &pFile, &ulFileLen);
            keyfile = argv[i + 1];

        }
        // Label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        }

        else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                 && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bFile) {
        printf("\n\tError: File name (-f) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }


    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");

        printf("\nImport a PEM encoded public key onto HSM.");
        printf("\n");
        printf
            ("\nSyntax: importPubKey -h -l <label> -f <filename>\n");
        printf("\t\t\t[-sess] [-id <key ID>]\n");
        printf
            ("\t\t\t[-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf("\n       -l       label for the new key");
        printf
            ("\n       -f       file containing the PEM encoded public key");
        printf("\n       -sess    specifies key as session key");
        printf("\n       -id      specifies key ID");
        printf
            ("\n       -min_srv specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                (till the time specified by -timeout option)");
        printf
            ("\n                if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }

    fp = fopen(keyfile, "rb");
    if (!fp) {
        ulRet = ERR_INVALID_INPUT;
        printf("unable to openfile\n");
        goto exit_error;
    }

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (pkey == NULL) {
        ulRet = ERR_INVALID_INPUT;
        printf("\n\t Failed to read Public Key from file %s\n", keyfile);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ulKeyType = get_key_type(pkey->type);
    if (ulKeyType < 0 || ulKeyType > 3) {
        printf("Error: Invalid Key Type %d\n", ulKeyType);
        ulRet = ERR_INVALID_INPUT;
        goto end;
    }

    switch (ulKeyType) {
    case KEY_TYPE_RSA:
        {
            char *pub_exp = NULL;
            rsa = EVP_PKEY_get1_RSA(pkey);
            if (rsa == NULL) {
                ulRet = ERR_INVALID_INPUT;
                printf("\n\t Failed to get RSA key from input file\n");
                ERR_print_errors_fp(stderr);
                goto end;
            }

            ulKeyDataLen = ulModLen = BN_num_bytes(rsa->n);

            pKeyData = (Uint8 *) CALLOC_WITH_CHECK(1, ulKeyDataLen);
            if (pKeyData == NULL)
                goto end;

            BN_bn2bin(rsa->n, (Uint8 *) pKeyData);
            pub_exp = BN_bn2dec(rsa->e);
            if (pub_exp) {
                ulPubExp = atoi(pub_exp);
                free(pub_exp);
                pub_exp = NULL;
            } else {
                printf("Error in getting the private exponent\n");
                ulRet = ERR_INVALID_INPUT;
                goto end;
            }
        }
        break;
    case KEY_TYPE_DSA:
        {
            dsa = EVP_PKEY_get1_DSA(pkey);
            if (dsa == NULL) {
                ulRet = ERR_INVALID_INPUT;
                printf("\n\t Failed to get DSA key from input file\n");
                ERR_print_errors_fp(stderr);
                goto end;
            }
            ulModLen = BN_num_bytes(dsa->p);
            ulKeyDataLen = i2d_DSA_PUBKEY(dsa, &pKeyData);
        }
        break;
    case KEY_TYPE_ECDSA:
        {
            ec_key = EVP_PKEY_get1_EC_KEY(pkey);
            if (ec_key == NULL) {
                ulRet = ERR_INVALID_INPUT;
                printf("\n\t failed to get EC_KEY from input file\n");
                ERR_print_errors_fp(stderr);
                goto end;
            }

            group = EC_KEY_get0_group(ec_key);
            ulCurveId = EC_GROUP_get_curve_name(group);

            ulKeyDataLen =
                EC_POINT_point2oct(group,
                                   EC_KEY_get0_public_key(ec_key),
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   NULL, 0, NULL);
            pKeyData = (Uint8 *) CALLOC_WITH_CHECK(1, ulKeyDataLen);
            if (pKeyData == NULL) {
                printf("Memory allocation failure \n");
                goto end;
            }
            EC_POINT_point2oct(group,
                               EC_KEY_get0_public_key(ec_key),
                               POINT_CONVERSION_UNCOMPRESSED,
                               pKeyData, ulKeyDataLen, NULL);
        }
        break;
    default:
        printf("Error: Invalid Key Type %d\n", ulKeyType);
        ulRet = ERR_INVALID_INPUT;
        goto end;
        break;
    }
    ulRet = Cfm3CreatePublicKey(session_handle,
                                ulKeyType, ulModLen,
                                ulPubExp, ulCurveId,
                                pKeyData, ulKeyDataLen,
                                NULL, 0,
                                (Uint8 *) pID, ulIDLen,
                                (Uint8 *) pLabel, ulLabelLen,
                                ucKeyLocation, &ulHandle, &request_id);

  end:
    printf("\n\tCfm3CreatePublicKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet == 0) {
        printf("\nPublic Key Handle: %llu \n", ulHandle);
    }

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulHandle, &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle, ulHandle, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        } else
            printf("\nPublic Key Handle: %llu \n", ulHandle);
    }

  exit_error:
    if (pID)
        free(pID);
    if (pLabel)
        free(pLabel);

    if (fp)
        fclose(fp);
    if (rsa)
        RSA_free(rsa);
    if (dsa)
        DSA_free(dsa);
    if (ec_key)
        EC_KEY_free(ec_key);
    if (pKeyData)
        free(pKeyData);
    if (pkey)
        EVP_PKEY_free(pkey);
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : exportPublicKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 exportPublicKey(int argc, char **argv)
{
    Uint32 ulRet = -1;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKeyHandle = 0;

    Uint8 bFile = FALSE;
    char *KeyFile = NULL;

    Uint32 ulModLen = 0;
    Uint32 ulKeyType = 0;
    Uint8 *pbKeyBuf = NULL, *pbKeyBuf2 = NULL;
    Uint32 ulDataLen = 0;
    FILE *fp = NULL;
    RSA *rsa = NULL;
    DSA *dsa = NULL;
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pub_key = NULL;
    Uint32 ulCurveId = 0;
    Uint32 ulAttrLen = 0;
    Uint8 pAttr[4] = { 0 };

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // Key Handle
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKey = readLongIntegerArg(argv[i + 1], &ulKeyHandle);

        else if ((!bFile) && (strcmp(argv[i], "-out") == 0) &&
                 (argc > i + 1)) {
            KeyFile = argv[i + 1];
            bFile = 1;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Key handle (-k) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bFile) {
        printf("\n\tError: Key File (-out) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nExport a public key in PEM encoded format.");
        printf("\n");
        printf
            ("\nSyntax: exportPubKey -h -k <key handle> -out <key file>\n");
        printf("\n");
        printf("\nWhere: -h    displays this information");
        printf("\n       -k    specifies the public key handle");
        printf
            ("\n       -out  specifies the file to write the exported public key");
        printf("\n\n");
        goto exit;
    }

    ulDataLen = 1024;
    pbKeyBuf = (Uint8 *) calloc(ulDataLen, 1);
    ulRet = Cfm3ExportPublicKey(session_handle,
                                ulKeyHandle, pbKeyBuf, &ulDataLen, NULL);
    if (ulRet == RET_RESULT_SIZE) {
        pbKeyBuf2 = (Uint8 *) realloc(pbKeyBuf, ulDataLen);
        if (pbKeyBuf2 == NULL) {
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto err;
        }
        else
            pbKeyBuf = pbKeyBuf2;

        if (pbKeyBuf) {
            ulRet = Cfm3ExportPublicKey(session_handle,
                                        ulKeyHandle, pbKeyBuf,
                                        &ulDataLen, NULL);
        } else {
            printf("\n\tError: Memory allocation errror.\n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto err;
        }
    }
    if (ulRet == RET_OK) {
        fp = fopen(KeyFile, "w");
        if (!fp) {
            ulRet = RET_INVALID_INPUT;
            goto err;
        }

        ulAttrLen = sizeof(pAttr);
        ulRet = Cfm3GetAttribute(session_handle,
                                 ulKeyHandle,
                                 OBJ_ATTR_KEY_TYPE, pAttr, &ulAttrLen,
                                 NULL, NULL, NULL);
        if (ulRet) {
            printf
                ("Cfm3GetAttribute to get key type failed %d : %s \n",
                 ulRet, Cfm2ResultAsString(ulRet));
            goto err;
        }
        ulKeyType = atoi((Int8 *) pAttr);

        switch (ulKeyType) {
        case KEY_TYPE_RSA:
            {
                ulModLen = ulDataLen / 2;
                rsa = RSA_new();
                if (rsa == NULL) {
                    printf("Failed to create RSA Key \n");
                    goto err;
                }

                if (!rsa->n && ((rsa->n = BN_new()) == NULL))
                    goto err;
                if (!rsa->e && ((rsa->e = BN_new()) == NULL))
                    goto err;

                /* Modulus */
                if (!BN_bin2bn(pbKeyBuf, ulModLen, rsa->n))
                    goto err;

                /* Public  Exponent */
                if (!BN_bin2bn(pbKeyBuf + (ulDataLen - 4), 4, rsa->e))
                    goto err;

                if (!PEM_write_RSA_PUBKEY(fp, rsa))
                    goto err;
            }
            break;
        case KEY_TYPE_DSA:
            {
                const unsigned char *key_buf = pbKeyBuf;

                dsa = d2i_DSA_PUBKEY(&dsa, &key_buf, ulDataLen);
                if (dsa == NULL) {
                    printf
                        ("Failed to convert into dsa: d2i_DSA_PUBKEY failed \n");
                    goto err;
                }

                if (!PEM_write_DSA_PUBKEY(fp, dsa))
                    goto err;
            }
            break;
        case KEY_TYPE_ECDSA:
            {
                const unsigned char *key_buf = pbKeyBuf;

                ulAttrLen = sizeof(pAttr);
                ulRet = Cfm3GetAttribute(session_handle,
                                         ulKeyHandle,
                                         OBJ_ATTR_MODULUS_BITS,
                                         pAttr, &ulAttrLen, NULL, NULL,
                                         NULL);
                if (ulRet) {
                    printf
                        ("Cfm3GetAttribute failed %d : %s \n",
                         ulRet, Cfm2ResultAsString(ulRet));
                    goto err;
                }
                ulCurveId = atoi((Int8 *) pAttr);
                group = EC_GROUP_new_by_curve_name(ulCurveId);
                if (group == NULL) {
                    printf("unable to create curve id %d\n", ulCurveId);
                    ulRet = ERR_UNSUPPORTED_CURVE; 
                    goto err;
                }

                EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
                EC_GROUP_set_point_conversion_form(group,
                                                   POINT_CONVERSION_UNCOMPRESSED);

                eckey = EC_KEY_new();
                if (eckey == NULL) {
                    printf("Failed to create ec key\n");
                    ulRet = ERR_MEMORY_ALLOC_FAILURE; 
                    goto err;
                }

                if (EC_KEY_set_group(eckey, group) == 0) {
                    printf("unable to set the group (%d)\n", ulCurveId);
                    ulRet = ERR_INVALID_INPUT; 
                    goto err;
                }
                pub_key = EC_POINT_new(EC_KEY_get0_group(eckey));
                if (pub_key == NULL) {
                    printf("Failed to create ec pub key\n");
                    ulRet = ERR_MEMORY_ALLOC_FAILURE; 
                    goto err;
                }

                EC_POINT_oct2point(group, pub_key, key_buf,
                                   ulDataLen, NULL);
                EC_KEY_set_public_key(eckey, (const EC_POINT *)
                                      pub_key);

                if (!PEM_write_EC_PUBKEY(fp, eckey)) {
                    printf("unable to write key \n");
                    ulRet = ERR_WRITE_OUTPUT_FILE; 
                    goto err;
                }
            }
            break;
        default:
            printf("\n\tError: Invalid Key Type: 0x%02x\n", ulKeyType);
            ulRet = ERR_INVALID_INPUT;
            goto err;
        }
        printf("\nPEM formatted public key is written to %s\n", KeyFile);
    }
  err:
    printf("\n\tCfm3ExportPubKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

  exit:
    if (fp)
        fclose(fp);
    if (rsa)
        RSA_free(rsa);
    if (dsa)
        DSA_free(dsa);
    if (eckey)
        EC_KEY_free(eckey);
    if (group)
        EC_GROUP_free(group);
    if (pub_key)
        EC_POINT_free(pub_key);
    if (pbKeyBuf)
        free(pbKeyBuf);
    return ulRet;
}

Uint8 KEK_key_unwrap(Uint8 * kek, Uint8 * wrappedKey, Uint32 wrappedKeyLen,
                     Uint8 * IV, Uint8 * plainKey, Uint32 * plainKeyLen)
{
    AES_KEY keyToSend;
    int cond_code = 0;

    AES_set_decrypt_key((const unsigned char *) kek, 256, &keyToSend);

    cond_code = AES_unwrap_key(&keyToSend, (const unsigned char *) IV,
                               (unsigned char *) plainKey,
                               (const unsigned char *)
                               wrappedKey, (unsigned int) (wrappedKeyLen));
    if (!cond_code) {
        return 1;
    }
    {

        *plainKeyLen = cond_code;
        *plainKeyLen -= plainKey[*plainKeyLen - 1];     //Should discard the pad bytes added by firmware

        return 0;

    }
}

int get_kek_from_file(char *file, Uint8 * kek)
{
    FILE *fptr = NULL;
    fptr = fopen(file, "r");
    if (fptr == NULL) {
        printf("Unable to open file %s. Returning..\n", KEK_FILE);
        return -1;
    }
    if (fread(kek, KEK_SIZE, 1, fptr) != 1) {
        printf("Failed to read from file: %s\n", KEK_FILE);
        fclose(fptr);
        fptr = NULL;
        return -1;
    }
    if (fptr)
        fclose(fptr);
    return 0;
}

static inline Uint32 set_iv_based_fw_ver(Uint8 *iv_out, uint8_t len,
                                         bool isRandom, bool isLatest)
{
    Uint32 ulRet = 0;

    if (isLatest == true) {
        memset(iv_out, 0, len);
    } else {
        if (isRandom == true) {
            if (RAND_bytes(iv_out, len) <= 0) {
                printf("\n\tRandom bytes get failed\n");
                ulRet = ERR_GENERAL_ERROR;
                goto end;
            }
        }
    }
end:
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : exportPrivateKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 exportPrivateKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bWrappingKey = FALSE;
    Uint32 ulWrappingKey = 0;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bFile = FALSE;
    char *KeyFile = NULL;

    Uint32 ulMech = CRYPTO_MECH_AES_KEY_WRAP_PAD;

    Uint64 randomIV = 0ULL;
    Uint8 *pIV = (Uint8 *) & randomIV;

    Uint8 *pKey = NULL, *pWrappedKey = NULL;
    Uint32 ulWrappedKeyLen = 0;
    Uint32 ulKeyLen = 0;
    Uint32 attr_len = 0;
    Uint32 ulKeyClass = OBJ_CLASS_PRIVATE_KEY;
    BIO *mem_bio = BIO_new(BIO_s_mem());
    BIO *file_bio = BIO_new(BIO_s_file());
    EVP_PKEY *pkey = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
#ifndef _WIN32
    Uint8 kek_buf[KEK_SIZE] = { };
#else
    Uint8 kek_buf[KEK_SIZE] = { 0 };
#endif
    Uint32 kek_len = 0;

    Uint8 bWFile = FALSE;
    char *pWFile = 0;
    bool latest_fw = false;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // wrapping key
        else if ((!bWrappingKey) && (strcmp(argv[i], "-w") == 0)
                 && (argc > i + 1))
            bWrappingKey = readIntegerArg(argv[i + 1], &ulWrappingKey);

        // private key file
        else if ((!bWFile) && (strcmp(argv[i], "-wk") == 0)
                 && (argc > i + 1)) {
            pWFile = argv[i + 1];
            bWFile = TRUE;
        }
        //  key
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);
        else if ((strcmp(argv[i], "-m") == 0) && (argc > i + 1)) {
            (void) readIntegerArg(argv[i + 1], (Uint32 *) & ulMech);
            ulMech = get_wrap_mechanism(ulMech);
        } else if ((!bFile) && (strcmp(argv[i], "-out") == 0) &&
                   (argc > i + 1)) {
            KeyFile = argv[i + 1];
            bFile = 1;
        } else
            bHelp = TRUE;

    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Key handle (-k) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bWrappingKey) {
        printf("\n\tError: Wrapping key handle (-w) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bFile) {
        printf("\n\tError: Key File (-out) is missing.\n");
        bHelp = TRUE;
    }
    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nExport a private key.");
        printf("\n");
        printf
            ("\nSyntax: exportPrivateKey -h -k <key handle> -w <wrapping key handle> -out <key file>\n");
        printf("\t\t\t [-m <wrapping mechanism>] [-wk <unwrapping key file>]\n");
        printf("\n");
        printf("\nWhere: -h   displays this information");
        printf("\n       -k   specifies the private key handle to export");
        printf("\n       -w   specifies the wrapping key handle");
        printf
            ("\n       -m   specifies the wrapping mechanism (Optional)");
        printf("\n            NIST_AES_WRAP - 4");
        printf
            ("\n       -out specifies the file to write the exported private key");
        printf
            ("\n       -wk  specifies the unwrapping key file if the unwrapping has to be done without the HSM");
        printf("\n\n");
        goto err;
    }

    if (bWFile) {
        ulRet = read_file((char *) pWFile, kek_buf, sizeof(kek_buf), &kek_len);
        if (kek_len != 16 && kek_len != 24 && kek_len != 32) {
            printf("\nInvalid file. Should be an AES key\n");
            ulRet = -1;
            goto err;
        }

    }

    attr_len = sizeof(ulKeyClass);
    if ((ulRet = Cfm3GetAttribute(session_handle,
                                  ulKey,
                                  OBJ_ATTR_CLASS,
                                  (Uint8 *) & ulKeyClass,
                                  &attr_len, NULL, NULL, NULL)) == 0) {
        ulKeyClass = atoi((Int8 *) & ulKeyClass);
        if (ulKeyClass != OBJ_CLASS_PRIVATE_KEY) {
            printf("\n\t%d is not a private key\n", (int) ulKey);
            ulRet = ERR_INVALID_INPUT;
            goto err;
        }
    }



    pKey = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    pWrappedKey = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    if (!pKey || !pWrappedKey) {
        printf("Memory allocation failure\n");
        ulRet = -1;
        goto err;
    }
    ulKeyLen = ulWrappedKeyLen = BUFSIZE;

    ulRet = is_fw_newset_with_aes_nist_pad(session_handle,
                                           MAJOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           MINOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           BUILD_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           &latest_fw);
    if (ulRet)
        goto err;

    ulRet = set_iv_based_fw_ver(pIV, 8, true, latest_fw);
    if (ulRet)
        goto err;

    ulRet = Cfm3ExportWrapKey(session_handle,
                              ulWrappingKey,
                              ulKey, pIV, pWrappedKey,
                              &ulWrappedKeyLen, NULL, latest_fw);

    printf("\n\tCfm3ExportWrapKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet) {
        goto err;
    }
    if (!bWFile) {
        ulRet = Cfm3ExportUnwrapKey(session_handle,
                                    pWrappedKey,
                                    ulWrappedKeyLen,
                                    pKey,
                                    &ulKeyLen, ulWrappingKey,
                                    pIV, NULL, latest_fw);
        printf("\n\tCfm3ExportUnwrapKey returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        if (ulRet) {
            goto err;
        }
    } else {
        ulRet = unwrap_key_on_host(session_handle, ulWrappedKeyLen, pWrappedKey,
                                    kek_len, kek_buf, &ulKeyLen, pKey,
                                    latest_fw ? NULL : pIV,
                                    CRYPTO_MECH_AES_KEY_WRAP_PAD, latest_fw);
        if (ulRet) {
            printf("AES_unwrap_key failed\n");
            ulRet = -1;
            goto err;
        }
    }

    if (BIO_write(mem_bio, (char *) pKey, ulKeyLen) <= 0) {
        printf("Couldn't write to mem_bio\n");
        ulRet = ERR_GENERAL_ERROR;
        goto err;
    }

    p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(mem_bio, NULL);
    if (p8inf == 0) {
        printf("failed to convert to pkcs8 format\n\n");
        ulRet = ERR_GENERAL_ERROR;
        goto err;
    }

    pkey = EVP_PKCS82PKEY(p8inf);
    if (pkey == 0) {
        printf("failed to convert to pkcs8 format\n\n");
        ulRet = ERR_GENERAL_ERROR;
        goto err;
    }

    if (BIO_write_filename(file_bio, KeyFile) <= 0) {
        printf("failed to open file bio\n\n");
        goto err;
    }

    if (!PEM_write_bio_PrivateKey
        (file_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        printf("failed to write to file\n\n");
        ulRet = ERR_GENERAL_ERROR;
    }
    printf("\nPEM formatted private key is written to %s\n", KeyFile);

  err:

    if (p8inf)
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (pKey)
        free(pKey);
    if (pWrappedKey)
        free(pWrappedKey);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (mem_bio)
        BIO_free(mem_bio);
    if (file_bio)
        BIO_free(file_bio);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : importPrivateKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 importPrivateKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;
    Uint32 ulModLen = 0;

    int k=0;
    Uint8 bWrappingKeyHandle = FALSE;
    Uint32 ulWrappingKeyHandle = 0;

    Uint8 bFile = FALSE;
    char *pFile = 0;

    Uint8 bWFile = FALSE;
    char *pWFile = 0;

    Uint8 bID = FALSE;
    Uint8 *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    Uint8 *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulCount = 0;

    Uint64 ulNewKey = 0;

    Int32 ulKeyType = 0;

    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    DSA *dsa = NULL;
    EC_KEY *ec_key = NULL;
    RSA *rsa = NULL;

    BIO *mem_bio = BIO_new(BIO_s_mem());

    Uint8 bAttest = FALSE;
    Uint8 *attestedResponse = NULL;
    Uint32 attestedLength = MTU_SIZE;

    Uint8 *pKey = NULL;
    Uint32 ulKeyLen = 0;
    Uint8 *pWrappedKey = NULL;
    Uint32 ulWrappedKeyLen = 0;
    Uint8 *pTemplate = NULL;
    Uint32 ulTemplateSz = 0, ulAtribCount = 0;

    Uint32 ulPubExp = 0;
#ifndef _WIN32
    Uint8 kek_buf[32] = { };
#else
    Uint8 kek_buf[32] = { 0 };
#endif
    Uint32 kek_len = 0;

    Uint32 ulCurveId = 0;
    Uint64 randomIV = 0ULL;
    Uint8 *pIV = (Uint8 *) & randomIV;

    Uint8 bMValue = FALSE;
    Uint8 ulMValue = 0;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;
    bool latest_fw = false;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // wrapping key handle
        else if ((strcmp(argv[i], "-w") == 0) && (argc > i + 1))
            bWrappingKeyHandle =
                readIntegerArg(argv[i + 1], &ulWrappingKeyHandle);
        // private key file
        else if ((!bFile) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1)) {
            pFile = argv[i + 1];
            bFile = TRUE;
        }
        // private key file
        else if ((!bWFile) && (strcmp(argv[i], "-wk") == 0)
                 && (argc > i + 1)) {
            pWFile = argv[i + 1];
            bWFile = TRUE;
        }
        // Label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel =
                readArgAsString(argv[i + 1], (char **) &pLabel,
                                &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], (char **) &pID, &ulIDLen);

        else if ((!bMValue) && (strcmp(argv[i], "-m_value") == 0)
                 && (argc > i + 1)) {
            ulMValue = atoi(argv[i + 1]);
            bMValue = TRUE;
            if (ulMValue > MAX_USERS_SHARED)
                bHelp = TRUE;
        }
        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            char *pTemp = NULL;
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulCount);

            if (pTemp)
                free(pTemp);
        }

        else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                 && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        } else if ((!bAttest) && (strcmp(argv[i], "-attest") == 0)
                   && (argc > i)) {
            bAttest = TRUE;
            i--;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bWrappingKeyHandle) {
        printf("\n\tError: wrapping Key handle (-w) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bFile) {
        printf("\n\tError: File name (-f) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if ((STORAGE_RAM == ucKeyLocation) && bUsers) {
        printf("\n\tError: sharing session keys is not allowed\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nImports RSA/DSA/EC Private Key.");
        printf("\n");
        printf
            ("\nSyntax: importPrivateKey -h -l <label> -f <private key file name> -w <wrapper key handle>\n");
        printf("\t\t\t[-sess] [-id <key ID>] [-m_value <0..8>]\n");
        printf
            ("\t\t\t[-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf
            ("\t\t\t[-u <user-ids>] [-wk <wrapping key file>][-attest]\n");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf("\n       -l       specifies the private key label");
        printf
            ("\n       -f       specifies the filename containing the key to import");
        printf
            ("\n       -w       specifies the wrapping key handle (KEK handle - 4)");
        printf("\n       -sess    specifies key as session key");
        printf
            ("\n       -attest  performs the attestation check on the firmware response");
        printf("\n       -id      specifies key ID");
        printf
            ("\n       -u       specifies the list of users to share with (separated by ,) (optional)");
        printf
            ("\n       -wk      specifies the wrapping key if the wrapping has to be done without the HSM");
        printf("\n       -m_value set the M value for the key");
        printf
            ("\n       -min_srv specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                (till the time specified by -timeout option)");
        printf
            ("\n                if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }
    if (bWFile) {
        ulRet = read_file((char *) pWFile, kek_buf, sizeof(kek_buf), &kek_len);
        if (kek_len != 16 && kek_len != 24 && kek_len != 32) {
            printf("\nInvalid file. Should be an AES key\n");
            ulRet = -1;
            goto end;
        }
    }


    fp = fopen(pFile, "rb");

    if (!fp) {
        printf("failed to open file  %s : %s\n", pFile, strerror(errno));
        ulRet = ERR_OPEN_FILE;
        goto err;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (pkey == NULL) {
        printf("failed to read private key from file\n\n");
        ulRet = ERR_INVALID_INPUT;
        goto err;
    }

    ulKeyType = get_key_type(pkey->type);
    if (ulKeyType < 0 || ulKeyType > 3) {
        printf("Error: Invalid Key Type %d\n", ulKeyType);
        ulRet = ERR_INVALID_INPUT;
        goto err;
    }

    ulRet = i2d_PKCS8PrivateKeyInfo_bio(mem_bio, pkey);
    if (ulRet == 0) {
        printf("failed to convert to pkcs8 format\n\n");
        ulRet = ERR_INVALID_USER_INPUT;
        goto err;
    }

    pKey = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    pWrappedKey = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    ulWrappedKeyLen = BUFSIZE;
    pTemplate = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);

    if (!pKey || !pWrappedKey || !pTemplate) {
        printf("Memory allocation failure \n");
        ulRet = ERR_MEMORY_ALLOC_FAILURE;
        goto err;
    }

    ulKeyLen = BIO_read(mem_bio, (char *) pKey, BUFSIZE);
    if (ulKeyLen == 0) {
        printf("Couldn't read from the mem_bio\n");
        ulRet = ERR_INVALID_USER_INPUT;
        goto err;
    }

    switch (ulKeyType) {
    case KEY_TYPE_RSA:
        {
            char *pub_exp = NULL;
            Uint8 *priv_exp = NULL;
            rsa = EVP_PKEY_get1_RSA(pkey);
            if (rsa == NULL) {
                printf("failed to read rsa private key from file\n\n");
                ulRet = ERR_INVALID_USER_INPUT;
                goto err;
            }
            priv_exp = (Uint8 *) OPENSSL_malloc(BN_num_bytes(rsa->d));
            if (priv_exp == NULL) {
                printf(" Memory allocation failure \n");
                ulRet = ERR_MEMORY_ALLOC_FAILURE;
                goto err;
            }

            BN_bn2bin(rsa->d, priv_exp);
            if (!priv_exp) {
                printf("Error in getting the private exponent\n");
                ulRet = ERR_INVALID_INPUT;
                goto err;
            }


            if ((*(Uint32 *) priv_exp == CAV_SIG_IMPORTED_KEY) ||
                (*(Uint32 *) priv_exp == CAV_SIG_HSM_KEY)) {
                printf
                    ("\nThis key is already imported with handle %lld\n\n",
                     *(Uint64 *) & priv_exp[8]);
                ulRet = ERR_INVALID_USER_INPUT;
                if (priv_exp) {
                    free(priv_exp);
                    priv_exp = NULL;
                }
                goto err;
            }
            if (priv_exp) {
                free(priv_exp);
                priv_exp = NULL;
            }

            pub_exp = BN_bn2dec(rsa->e);
            if (pub_exp) {
                ulPubExp = atoi(pub_exp);
                free(pub_exp);
                pub_exp = NULL;
            } else {
                printf("Error in getting the private exponent\n");
                ulRet = ERR_INVALID_INPUT;
                goto err;
            }
            ulModLen = BN_num_bytes(rsa->n);
        }
        break;
    case KEY_TYPE_DSA:
        {
            dsa = EVP_PKEY_get1_DSA(pkey);
            if (dsa == NULL) {
                printf("failed to read dsa private key from file\n\n");
                ulRet = ERR_INVALID_USER_INPUT;
                goto err;
            }
            ulModLen = BN_num_bytes(dsa->p);
        }
        break;
#if 0
        TODO - Enable this while testing
    the DH keys case KEY_TYPE_DH:{
            }
        break;
#endif
    case KEY_TYPE_ECDSA:
        {
            ec_key = EVP_PKEY_get1_EC_KEY(pkey);
            if (!ec_key) {
                printf
                    ("\n \tfailed to read ecdsa private key from file\n");
                ulRet = ERR_INVALID_USER_INPUT;
                goto err;
            }
            ulCurveId = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
        }
        break;
    default:
        ulRet = ERR_INVALID_USER_INPUT;
        goto err;
    }
    printf("BER encoded key length is %d\n", ulKeyLen);

    ulRet = is_fw_newset_with_aes_nist_pad(session_handle,
                                           MAJOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           MINOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           BUILD_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           &latest_fw);
    if (ulRet)
        goto err;

    ulRet = set_iv_based_fw_ver(pIV, 8, true, latest_fw);
    if (ulRet)
        goto err;

    /* wrap the key */
    for (k=0;k<100;k++){
    if (!bWFile) {
        ulRet = Cfm3ImportWrapKey(session_handle,
                                  pKey,
                                  ulKeyLen,
                                  ulWrappingKeyHandle, pIV,
                                  pWrappedKey, &ulWrappedKeyLen,
                                  NULL, latest_fw);
        printf("\n\tCfm3ImportWrapKey returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        if (ulRet) {
            goto end;
        }
    } else {
        ulRet = wrap_key_on_host(session_handle, ulKeyLen, pKey,
                                 kek_len, kek_buf,
                                 &ulWrappedKeyLen, pWrappedKey,
                                 (latest_fw == true) ? NULL : pIV,
                                 CRYPTO_MECH_AES_KEY_WRAP_PAD, latest_fw);
        if (ulRet) {
            printf("AES_wrap_key failed\n");
            ulRet = -1;
            goto end;
        }
    }

    ulRet = Cfm3CreateUnwrapTemplate(OBJ_CLASS_PRIVATE_KEY,
                                     ulKeyType,
                                     ucKeyLocation,
                                     pUsers, ulCount,
                                     ulMValue,
                                     pID, ulIDLen,
                                     pLabel, ulLabelLen,
                                     ulKeyLen,
                                     ulModLen * 8,
                                     ulPubExp,
                                     ulCurveId,
                                     pTemplate,
                                     &ulTemplateSz, &ulAtribCount);

    printf("\n\tCfm3CreateUnwrapTemplate returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet) {
        goto end;
    }

    if (bAttest) {
        attestedResponse = (Uint8 *) CALLOC_WITH_CHECK(1, attestedLength);

        if (!attestedResponse) {
            printf("Memory allocation failure \n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto exit_error;
        }
    }

    /* unwrap the key on HSM */
    ulRet = Cfm3ImportUnWrapKey(session_handle,
                                pWrappedKey, ulWrappedKeyLen,
                                ulWrappingKeyHandle,
                                pIV,
                                pTemplate, ulTemplateSz,
                                ulAtribCount,
                                &ulNewKey,
                                attestedResponse, &attestedLength,
                                &request_id, ucKeyLocation, latest_fw);

    printf("\n\tCfm3ImportUnWrapKey: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    }
  err:
  end:

    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf("\n\tPrivate Key Imported.  Key Handle: %llu \n",
               ulNewKey);
        if (bAttest) {
            if (attestedLength)
                if (verifyAttestation
                    (session_handle, (Uint8 *) attestedResponse,
                     attestedLength)) {
                    ulRet = ERR_ATTESTATION_CHECK;
                }
        }
    }

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulNewKey, &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle, ulNewKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        } else
            printf("\n\tPrivate Key Imported.  Key Handle: %llu \n",
                   ulNewKey);


    }

  exit_error:
    if (attestedResponse)
        free(attestedResponse);
    if (fp)
        fclose(fp);
    if (pWrappedKey)
        free(pWrappedKey);
    if (pTemplate)
        free(pTemplate);
    if (pKey)
        free(pKey);
    if (rsa)
        RSA_free(rsa);
    if (dsa)
        DSA_free(dsa);
    if (ec_key)
        EC_KEY_free(ec_key);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (mem_bio)
        BIO_free(mem_bio);

    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);
    return ulRet;
}



/****************************************************************************
 *
 * FUNCTION     : genPBEKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 genPBEKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint64 ulKey = 0;

    Uint8 bCount = FALSE;
    Uint32 ulCount = 0;

    Uint8 bSalt = FALSE;
    char *pSalt = 0;
    Uint32 ulSaltLen = 0;

    Uint8 bPassword = FALSE;
    char *pPassword = 0;
    Uint32 ulPasswordLen = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;

    Uint8 IV[8];
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulUserCount = 0;

    Uint8 bMValue = FALSE;
    Uint8 ulMValue = 0;

    KeyGenAttest *attest_info = NULL;
    Uint8 attest = FALSE;

    Uint8 bNextractable = FALSE;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;
    char *pTemp = NULL;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // count
        else if ((!bCount) && (strcmp(argv[i], "-c") == 0)
                 && (argc > i + 1))
            bCount = readIntegerArg(argv[i + 1], &ulCount);

        // password
        else if ((!bPassword) && (strcmp(argv[i], "-p") == 0)
                 && (argc > i + 1))
            bPassword =
                readArgAsString(argv[i + 1], &pPassword, &ulPasswordLen);

        // salt
        else if ((!bSalt) && (strcmp(argv[i], "-s") == 0)
                 && (argc > i + 1))
            bSalt = readArgAsString(argv[i + 1], &pSalt, &ulSaltLen);

        // label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulUserCount);
        } else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        }

        else if (strcmp(argv[i], "-nex") == 0) {
            bNextractable = TRUE;
            i--;
        }

        else if ((!bMValue) && (strcmp(argv[i], "-m_value") == 0)
                 && (argc > i + 1)) {
            ulMValue = atoi(argv[i + 1]);
            bMValue = TRUE;
            if (ulMValue > MAX_USERS_SHARED)
                bHelp = TRUE;
        }

        else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                 && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        }



        else if (strcmp(argv[i], "-attest") == 0) {
            attest = TRUE;
            i--;
        }

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bCount) {
        printf("\n\tError: Iteration count (-c) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bPassword) {
        printf("\n\tError: Password (-p) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bSalt) {
        printf("\n\tError: Salt value (-s) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if ((STORAGE_RAM == ucKeyLocation) && bUsers) {
        printf("\n\tError: sharing session keys is not allowed\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nGenerates a PBE DES3 key.");
        printf("\n");
        printf
            ("\nSyntax: genPBEKey -h -l <label > -p <password> -s <salt> -c <iteration count>\n");
        printf("\t\t\t[-sess] [-nex] [-id <key ID>] [-attest]\n");
        printf("\t\t\t[-u <user-ids>] [-m_value <0..8>]\n");
        printf
            ("\t\t\t[-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h        displays this information");
        printf("\n       -l        specifies the key label");
        printf("\n       -p        specifies the password");
        printf("\n       -s        specifies the salt value: eg. name");
        printf
            ("\n       -c        specifies the iteration count <= 10000: eg. 10");
        printf("\n       -sess     specifies key as session key");
        printf("\n       -id       specifies key ID");
        printf("\n       -nex      set the key as non-extractable");
        printf
            ("\n       -u        specifies the list of users to share with (separated by ,) (optional)");
        printf
            ("\n       -attest   performs the attestation check on the firmware response");
        printf
            ("\n       -min_srv  specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                 (till the time specified by -timeout option)");
        printf
            ("\n                 if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout  specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                 If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }
    if (attest) {
        attest_info = calloc(sizeof(*attest_info), 1);

        if (!attest_info) {
            printf("couldn't allocate attest info\n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto exit_error;
        }
    }


    ulKey = 0;

    ulRet = Cfm3GeneratePBEKey(session_handle,
                               (Uint16 *) pUsers, ulUserCount, ulMValue,
                               (Uint8 *) pID, ulIDLen,
                               (Uint8 *) pLabel, ulLabelLen,
                               (Uint8 *) pPassword, ulPasswordLen,
                               (Uint8 *) pSalt, ulSaltLen,
                               ulCount, IV, ucKeyLocation, 0,
                               !bNextractable, &ulKey, attest_info,
                               &request_id);
    printf("\n\tCfm3GeneratePBEKey returned: 0x%02x %s%s\n", ulRet,
           ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf("\n\tPBE Key Created.  Key Handle: %llu\n", ulKey);
        if (attest) {
            ulRet =
                verifyAttestation(session_handle, (Uint8 *) attest_info,
                                  sizeof(*attest_info));
            if (ulRet) {
                ulRet = ERR_ATTESTATION_CHECK;
            }
        }
    }

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet = Cfm3FindSingleKey(session_handle, ulKey, &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle, ulKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        }
    }

  exit_error:

    if (attest_info)
        free(attest_info);
    if (pPassword)
        free(pPassword);
    if (pSalt)
        free(pSalt);
    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);
    if (pTemp)
        free(pTemp);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : wrapKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 wrapKey(int argc, char **argv)
{
    Uint32 i = 0;
    Uint32 ulRet = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;
    Uint8 bFile = FALSE;
    char *KeyFile = NULL;

    Uint8 bWrappingKeyHandle = FALSE;
    Uint64 ulWrappingKeyHandle = 0;

    Uint64 randomIV = 0ULL;
    Uint8 *pIV = (Uint8 *) & randomIV;

    Uint8 *pWrappedKey = NULL;
    Uint32 ulWrappedKeyLen = BUFSIZE;
   
    Uint8 *pData = NULL;

    Uint32 ulIVLen = 8;
    bool isLatest = false;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        // wrapping key handle
        else if ((strcmp(argv[i], "-w") == 0) && (argc > i + 1))
            bWrappingKeyHandle =
                readLongIntegerArg(argv[i + 1], &ulWrappingKeyHandle);
        // key to be wrapped
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);
        else if ((!bFile) && (strcmp(argv[i], "-out") == 0)
                 && (argc > i + 1)) {
            KeyFile = argv[i + 1];
            bFile = 1;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bWrappingKeyHandle) {
        printf("\n\tError: wrapping Key handle (-w) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bKey) {
        printf("\n\tError: key to be wrapped (-k) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bFile) {
        printf("\n\tError: Wrapped Key File (-out) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nWraps sensitive keys from HSM to host.");
        printf("\n");
        printf
            ("\nSyntax: wrapKey -h -k <key to be wrapped> -w <wrapping key handle> -out <wrapped key file>\n");
        printf("\n");
        printf("\nWhere: -h    displays this information");
        printf("\n       -k    handle of the key to be wrapped");
        printf
            ("\n       -w    specifies the wrapping key handle (KEK handle - 4)");
        printf
            ("\n       -out  specifies the file to write the wrapped key data");
        printf("\n\n");
        goto exit_out;
    }

    pData = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);

    if (pData == NULL) {
        printf("pData mem allocation failed\n");
        ulRet = ERR_MEMORY_ALLOC_FAILURE;
        goto exit_out;
    }

    /* Store Wrapping Key Handle
     * Wrapping KeyHandle followed by IV
     * followed by wrapped key data
     */
    pIV = (Uint8 *)(pData);
    pWrappedKey = pIV + ulIVLen;

    ulRet = is_fw_newset_with_aes_nist_pad(session_handle,
                                           MAJOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           MINOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           BUILD_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           &isLatest);
    if (ulRet)
        goto exit_out;

    ulRet = set_iv_based_fw_ver(pIV, 8, true, isLatest);
    if (ulRet)
        goto exit_out;

    ulRet = Cfm3WrapKeyWithTemplate(session_handle,
                                    ulWrappingKeyHandle,
                                    ulKey, pIV, pWrappedKey,
                                    &ulWrappedKeyLen, NULL);
    if (ulRet == 0) {
        printf("\n\tKey Wrapped.\n");
        // write to a file
        if (WriteBinaryFile
            (KeyFile, (char *) pData,
             + ulIVLen + ulWrappedKeyLen)) {
            printf("\n\tWrapped Key written to file \"%s\" length %d\n", KeyFile, ulWrappedKeyLen);
        } else {
            ulRet = ERR_WRITE_OUTPUT_FILE;
            printf("\n\tFailed to write Wrapped Key to a file.\n");
        }
    }
    printf("\n\tCfm3WrapKeyWithTemplate returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
exit_out:
    if (pData)
        free(pData);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : unWrapKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 unWrapKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint64 ulNewKey = 0;

    Uint8 *pIV = NULL;
    Uint32 ulIVLen = 8;

    Uint8 bWrappingKeyHandle = FALSE;
    Uint64 ulWrappingKeyHandle = 0;

    Uint8 ucKeyLocation = STORAGE_FLASH;
    Uint8 bKey = FALSE;
    char *pTemp = NULL;

    Uint8 bAttest = FALSE;
    Uint8 *attestedResponse = NULL;
    Uint32 attestedLength = MTU_SIZE;

    Uint8 pKey[4096] = { 0 };
    Uint32 ulKeyLen = 0;
    Uint8 *pWrappedKey = NULL;
    Uint32 ulWrappedKeyLen = 0;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;

    Uint32 ulMech = CRYPTO_MECH_AES_KEY_WRAP_PAD;
    Uint8 bMech = FALSE;


    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        // wrapping key handle
        else if ((strcmp(argv[i], "-w") == 0) && (argc > i + 1))
            bWrappingKeyHandle =
                readLongIntegerArg(argv[i + 1], &ulWrappingKeyHandle);
        // Mechanism
        else if ((!bMech) && (strcmp(argv[i], "-m") == 0)
                 && (argc > i + 1)) {
            bMech =
                readIntegerArg(argv[i + 1], (Uint32 *) & ulMech);
            if (!bMech || (ulMech < 4))
                bHelp = TRUE;
            ulMech = get_wrap_mechanism(ulMech);
            if (-1 == ulMech)
                bHelp = TRUE;
        // wrapped key
        } else if ((!bKey) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1)) {
            bKey = readFileArg(argv[i + 1], &pTemp, &ulKeyLen);
            if (bKey == TRUE && ulKeyLen <= sizeof(pKey))
                memcpy(&pKey[0], pTemp, ulKeyLen);
        } else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        } else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                   && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else if ((!bAttest) && (strcmp(argv[i], "-attest") == 0)
                   && (argc > i)) {
            bAttest = TRUE;
            i--;
        }
	else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bWrappingKeyHandle) {
        printf("\n\tError: wrapping key handle (-w) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bKey) {
        printf("\n\tError: Key filename (-f) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nunWraps sensitive key onto HSM.");
        printf("\n");
        printf
            ("\nSyntax: unWrapKey -h -f <key file name> -w <wrapper key handle>\n");
        printf("                  [-sess] [-attest] [-m <mechanism>]\n");
        printf
            ("                  [-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf
            ("\n       -f       specifies the filename containing the key to import");
        printf
            ("\n       -w       specifies the wrapper key handle, 4 for KEK");
        printf
            ("\n       -m  specifies the wrapping mechanism (Optional)");
        printf("\n               NIST_AES_WRAP_PAD - 4");
        printf("\n               NIST_AES_WRAP     - 5(if unwrapping old blob(wrapped fw_verion < 2.04)");
        printf("\n       -sess    specifies key as session key");
        printf
            ("\n       -attest  performs the attestation check on the firmware response");
        printf
            ("\n       -min_srv specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                (till the time specified by -timeout option)");
        printf
            ("\n                if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }

    /* Wrapped key is in the format 8 byte IV followed by 
     * Wrapped Key Data
     */
    pIV = pKey;
    pWrappedKey = pKey + ulIVLen;
    ulWrappedKeyLen = ulKeyLen - ulIVLen;

    if (bAttest) {
        attestedResponse = (Uint8 *) CALLOC_WITH_CHECK(1, attestedLength);
        if (!attestedResponse) {
            printf("Memory allocation failure \n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto exit_error;
        }
    }

    ulRet = Cfm2UnWrapKey5(session_handle,
                           ulWrappingKeyHandle,
                           pWrappedKey,
                           ulWrappedKeyLen,
                           pIV,
                           ulMech,
                           UNSUPPORTED_HASH,
                           0,
                           ucKeyLocation,
                           &ulNewKey,
                           attestedResponse,
                           &attestedLength,
                           &request_id);

    printf("\n\tCfm2UnWrapKey5 returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf("\n\tKey Unwrapped.  Key Handle: %llu \n",
               ulNewKey);
        if (bAttest) {
            if (attestedLength)
                if (verifyAttestation
                    (session_handle, (Uint8 *) attestedResponse,
                     attestedLength)) {
                    ulRet = ERR_ATTESTATION_CHECK;
                }
        }
    }
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulNewKey, &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle, ulNewKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        } else
            printf("\n\tKey Unwrapped.  Key Handle: %llu \n",
                   ulNewKey);

    }

  exit_error:
    if (attestedResponse)
        free(attestedResponse);

    return ulRet;
}

Uint32 unWrapKeyWithSize(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint8 bHelp = FALSE;
    Uint8 bKeyType = FALSE;
    Uint32 ulKeyType = -1;
    Uint8 bTemplate = FALSE;
    Uint8 bTemplateExists = FALSE;
    Uint8 bExtractable = FALSE;
    Uint8 bKeySize = FALSE;
    Uint32 ulKeySize = 0;
    char *pLabel = NULL;
    Uint32 ulLabelLen = 0;
    Uint8 bLabel = FALSE;
    Uint8 bMod = FALSE;
    Uint32 ulModLen = 0;
    Uint8 bWrappingKeyHandle = FALSE;
    Uint64 ulWrappingKeyHandle = 0;
    Uint8 bKey = FALSE;
    char *pTemp = NULL;
    Uint8 pKey[4096] = { 0 };
    Uint32 ulKeyLen = 0;
    Uint64 ulNewKey = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;
    Uint8 *pWrappedKey = NULL;
    Uint32 ulWrappedKeyLen = 0;

    Uint8 bIV = FALSE;
    Uint8 *pIV = NULL;
    Uint64 default_iv = KEY_WRAP_IV;
    Uint8 *pTempIV = NULL;
    Uint32 ulMech = CRYPTO_MECH_AES_KEY_WRAP_NO_PAD;
    Uint8 bMech = FALSE;
    bool isLatest = false;

    Uint16 i = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        // wrapping key handle
        else if ((strcmp(argv[i], "-w") == 0) && (argc > i + 1))
            bWrappingKeyHandle = readLongIntegerArg(argv[i + 1],
                                                    &ulWrappingKeyHandle);
        else if ((!bKey) && (strcmp(argv[i], "-f") == 0) &&
                 (argc > i + 1)) {
            bKey = readFileArg(argv[i + 1], &pTemp, &ulKeyLen);
            if (bKey == TRUE && ulKeyLen <= sizeof(pKey))
                memcpy(&pKey[0], pTemp, ulKeyLen);
        }
        // type
        else if ((!bKeyType) && (strcmp(argv[i], "-t") == 0) &&
                 (argc > i + 1))
            bKeyType = readIntegerArg(argv[i + 1], &ulKeyType);
        // key size
        else if ((!bKeySize) && (strcmp(argv[i], "-s") == 0) &&
                 (argc > i + 1))
            bKeySize = readIntegerArg(argv[i + 1], &ulKeySize);
        // Mod len
        else if ((!bMod) && (strcmp(argv[i], "-m") == 0) &&
                 (argc > i + 1)) {
            bMod = readIntegerArg(argv[i + 1], &ulModLen);

            if (TRUE == bMod) {
                if (0 == ulModLen) {
                    printf("\n\tmodules should not be zero\n");
                    bHelp = TRUE;
                }
            }
        }
        // label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0) &&
                 (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);
        else if ((!bTemplate) && (strcmp(argv[i], "-template") == 0)) {
            bTemplateExists = TRUE;
            i--;
        } else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;
        }else if (strcmp(argv[i], "-extractable") == 0) {
            bExtractable = TRUE;
            i--;
        } else if ((!bIV) && (strcmp(argv[i], "-i") == 0) &&
                   (argc > i + 1)) {
            Uint32 ulIVLen = 0;
            BIGNUM *n = NULL;
            bIV = readArgAsString(argv[i + 1], (char **) &pIV, &ulIVLen);
            n = BN_new();
            BN_hex2bn(&n, (char *) pIV);
            ulIVLen = BN_num_bytes(n);
            BN_bn2bin(n, pIV);
            BN_free(n);
            if (ulIVLen != AES_KEY_WRAP_IV_SIZE) {
                printf("\nError: Invalid IV length %d %s\n", ulIVLen, pIV);
                bHelp = TRUE;
            }
            pTempIV = pIV;
        } else if ((!bMech) && (strcmp(argv[i], "-mech") == 0) &&
                   (argc > i + 1)){
            bMech = readIntegerArg(argv[i + 1], &ulMech);
            if (FALSE == bMech) {
                printf("\nError: Invalid mech type passed\n");
                bHelp = TRUE;
            }
            ulMech = get_wrap_mechanism(ulMech);
            if (-1 == ulMech)
                bHelp = TRUE;
        } else
            bHelp = TRUE;
    }

    if (!bHelp && !bWrappingKeyHandle) {
        printf("\n\tError: wrapping key handle (-w) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bKey) {
        printf("\n\tError: Key filename (-f) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bKeyType) {
        printf("\n\tError: Key type (-t) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp) {
        if (!bKeySize) {
            if (((CRYPTO_MECH_AES_KEY_WRAP == ulMech) ||
                 (CRYPTO_MECH_AES_KEY_WRAP_NO_PAD == ulMech))) {
                printf("\n\tError: Key Size (-s) is missing for NIST_AES_WRAP_NO_PAD or NIST_AES_WRAP\n");
                bHelp = TRUE;
            }
        } else {
            if (CRYPTO_MECH_AES_KEY_WRAP_PKCS_PAD == ulMech) {
                printf("\n\tError: don't pass key size for CRYPTO_MECH_AES_KEY_WRAP_PKCS_PAD");
                bHelp = TRUE;
            }
        }
    }

    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && (FALSE == bTemplateExists) &&
        (KEY_TYPE_RSA == ulKeyType) && !bMod) {
        printf("\n\tError: Modulus size in bits (-m) is missing for RSA key type in no template case\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bIV) {
        printf("\n\tWarning: IV (-i) is missing.\n");
        printf("\t\t 0xA6A6A6A6A6A6A6A6/0x0 is considered as default IV based on fw ver\n");
        pTempIV = (Uint8 *) & default_iv;
    }

    if (!bHelp && !bMech) {
        printf("\n\t Warning: Mechanism for wrap/unwrap is missing.");
        printf("\n\t NIST_AES_WRAP_NO_PAD is the default mechanishm\n");
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nUnWrap key with size.");
        printf("\n");
        printf
            ("\nSyntax: unWrapKeyWithSize -h -f <key file name> -w <wrapper key handle>\n"
             "\t\t\t-l <label > -t <key type> -s <key size> -m modlen [-mech <4/5/10>]\n"
             "\t\t\t-i [<Unwrapping IV>] [-template] [-sess] [-extractable]");
        printf("\nWhere: -h       displays this information");
        printf("\n       -l       specifies the Key Label");
        printf("\n       -f       specifies the filename containing the key to unWrap");
        printf("\n       -w       specifies the wrapper key handle, 4 for KEK");
        printf("\n       -t       specifies the key type");
        printf("\n\t\t (0 = RSA, 1 = DSA, 3 = ECDSA,\n"
               "\t\t 16 = GENERIC_SECRET, 18 = RC4, 21 = DES3, 31 = AES, 19 = DES)");
        printf("\n       -s       specifies the key size in bytes"
               "\n                only needed for CRYPTO_MECH_AES_KEY_WRAP_PAD and CRYPTO_MECH_AES_KEY_WRAP_NO_PAD");
        printf("\n\t\t for RSA, DSA, ECDSA PKCS8 DER encoded length");
        printf("\n\t\t AES : 16, 24, 32");
        printf("\n\t\t 3DES : 24");
        printf("\n\t\t DES : 8");
        printf("\n\t\t RC4 : <256");
        printf("\n\t\t GENERIC_SECRET : <= 800");
        printf("\n       -m        Modulus size in bits(valid for asymmetric private keys(template case optional)),"
               "\n\t\t             if no template valid for RSA private key(mandatory)");
        printf("\n       -mech     specifies the mechanism(optional)");
        printf("\n                 4 for NIST_AES_WRAP_PAD");
        printf("\n                 5 for NIST_AES_WRAP_NO_PAD");
        printf("\n                 10 for CRYPTO_MECH_AES_KEY_WRAP_PKCS_PAD(if unwrapping old blob(wrapped fw version < 2.04))");
        printf("\n       -template use the template(optional)");
        printf("\n       -sess    specifies key as session key(optional)");
        printf("\n       -i       specifies the IV to be used(optional)");
        printf("\n       -extractable specifies key is extractable or not(optional)");
        printf("\n");
        goto exit_error;
    }

    ulRet = is_fw_newset_with_aes_nist_pad(session_handle,
                                           MAJOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           MINOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           BUILD_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           &isLatest);
    if (ulRet)
        goto exit_error;

    if (isLatest == false) {
        printf("API not supported on old firmware\n");
        goto exit_error;

    }

    if((ulMech == CRYPTO_MECH_AES_KEY_WRAP_PAD) && !bIV) {
        ulRet = set_iv_based_fw_ver(pTempIV, AES_KEY_WRAP_IV_SIZE, false,
                                    isLatest);
        if (ulRet)
            goto exit_error;
    }

    if (bTemplateExists == true) {
        printf("\n\tWARN IV is ignored for template case\n");
        pTempIV = pKey;
        pWrappedKey = pKey + AES_KEY_WRAP_IV_SIZE;
        ulWrappedKeyLen = ulKeyLen - AES_KEY_WRAP_IV_SIZE;
    } else {
        printf("\n\tWARN template option is missing.");
        printf("\n\tso unwrapping key without template.\n");
        pWrappedKey = pKey;
        ulWrappedKeyLen = ulKeyLen;
    }
    ulRet = Cfm3UnWrapKeyWithSize(session_handle,
                                  pWrappedKey,
                                  ulWrappedKeyLen,
                                  ulWrappingKeyHandle,
                                  pTempIV,
                                  ulKeyType,
                                  ulKeySize,
                                  ulModLen,
                                  bTemplateExists,
                                  pLabel, ulLabelLen,
                                  &ulNewKey,
                                  ucKeyLocation,
                                  bExtractable,
                                  ulMech);
    printf("\n\tCfm3UnWrapKeyWithSize: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (0 == ulRet)
        printf("\n\tKey Unwrapped.  Key Handle: %llu \n",
               ulNewKey);

exit_error:
    if (pIV)
        free(pIV);
    if (pLabel)
        free(pLabel);
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : genSymKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 genSymKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    int k=0;
    Uint64 ulKey = 0;

    Uint8 bKeyType = FALSE;
    Uint32 ulType = 0;

    Uint8 bSize = FALSE;
    Uint32 ulSize = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulCount = 0;

    Uint8 bMValue = FALSE;
    Uint8 ulMValue = 0;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;

    Uint8 bNextractable = FALSE;

    Uint8 attest = FALSE;

    KeyGenAttest *attest_info = NULL;
    char *pTemp = NULL;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // type
        else if ((!bKeyType) && (strcmp(argv[i], "-t") == 0)
                 && (argc > i + 1))
            bKeyType = readIntegerArg(argv[i + 1], &ulType);

        // size
        else if ((!bSize) && (strcmp(argv[i], "-s") == 0)
                 && (argc > i + 1))
            bSize = readIntegerArg(argv[i + 1], &ulSize);

        // label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulCount);
        }

        else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        }

        else if (strcmp(argv[i], "-nex") == 0) {
            bNextractable = TRUE;
            i--;
        }

        else if ((!bMValue) && (strcmp(argv[i], "-m_value") == 0)
                 && (argc > i + 1)) {
            ulMValue = atoi(argv[i + 1]);
            bMValue = TRUE;
            if (ulMValue > MAX_USERS_SHARED)
                bHelp = TRUE;
        }

        else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                 && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        }


        else if (strcmp(argv[i], "-attest") == 0) {
            attest = TRUE;
            i--;                //This for loops skips i by 2. so go with it.
        }

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKeyType) {
        printf("\n\tError: Key type (-t) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bSize) {
        printf("\n\tError: Key size (-s) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if ((STORAGE_RAM == ucKeyLocation) && bUsers) {
        printf("\n\tError: sharing session keys is not allowed\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nGenerates a Symmetric  keys.");
        printf("\n");
        printf
            ("\nSyntax: genSymKey -h -l <label > -t <key type> -s <key size>\n");
        printf("\t\t\t[-sess] [-id <key ID>] [-nex] [-attest]\n");
        printf("\t\t\t[-u <user-ids>] [-m_value <0..8>]\n");
        printf
            ("\t\t\t[-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf("\n       -l       specifies the Key Label");
        printf("\n       -t       specifies the key type");
        printf
            ("\n                (16 = GENERIC_SECRET, 18 = RC4, 21 = DES3, 31 = AES)");
        printf("\n       -s       specifies the key size in bytes");
        printf("\n                for AES : 16, 24, 32");
        printf("\n                    3DES: 24");
        printf("\n                    RC4 : <= 256");
        printf("\n                    GENERIC_SECRET: <= 800");
        printf("\n       -sess    specifies key as session key");
        printf("\n       -id      specifies key ID");
        printf("\n       -nex     set the key as non-extractable");
        printf
            ("\n       -u       specifies the list of users to share with (separated by ,) (optional)");
        printf
            ("\n       -m_value specifies the number of users to approve for any key service");
        printf
            ("\n       -min_srv specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                (till the time specified by -timeout option)");
        printf
            ("\n                if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                If nothing is specified, the polling will continue forever");
        printf
            ("\n       -attest  performs the attestation check on the firmware response\n");
        printf("\n");
        goto exit_error;
    }
    if (attest) {
        attest_info = calloc(sizeof(*attest_info), 1);

        if (!attest_info) {
            printf("couldn't allocate attest info\n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto exit_error;
        }
    }

    if ((fipsState >= 2) && (ulType == KEY_TYPE_RC4)) {
        printf("\n RC4 is not allowed in FIPS mode\n");
        printf("\n Current FIPS mode: %08x\n", fipsState);
        goto exit_error;
    }

    for (k=0;k<100;k++){
    ulKey = 0;
    ulRet = Cfm3GenerateSymmetricKey(session_handle,
                                     ulType, ulSize,
                                     (Uint16 *) pUsers, ulCount, ulMValue,
                                     (Uint8 *) pID, ulIDLen,
                                     (Uint8 *) pLabel, ulLabelLen,
                                     ucKeyLocation, !bNextractable, &ulKey,
                                     attest_info, &request_id);
    printf("\n\tCfm3GenerateSymmetricKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf("\n\tSymmetric Key Created.  Key Handle: %llu\n", ulKey);
        if (attest) {
            ulRet =
                verifyAttestation(session_handle, (Uint8 *) attest_info,
                                  sizeof(*attest_info));
            if (ulRet) {
                ulRet = ERR_ATTESTATION_CHECK;
            }
        }
    }
    }

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }

    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }

    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet = Cfm3FindSingleKey(session_handle, ulKey, &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle, ulKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        } else
            printf("\n\tSymmetric Key Created.  Key Handle: %llu\n",
                   ulKey);

    }

  exit_error:
    if (attest_info)
        free(attest_info);
    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);
    if (pTemp)
        free(pTemp);

    return ulRet;
}

Uint32 exSymKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bFile = FALSE;
    char *KeyFile = NULL;

    Uint8 bWrappingKey = FALSE;
    Uint64 ulWrappingKey = 0;

    Uint64 randomIV = 0ULL;
    Uint8 *pIV = (Uint8 *) & randomIV;

    Uint32 ulMech = CRYPTO_MECH_AES_KEY_WRAP_PAD;

    Uint8 *pKey = NULL;
    Uint32 ulKeyLen = 0;
    Uint8 *pWrappedKey = NULL;
    Uint32 ulWrappedKeyLen = 0;

    Uint32 ulTemp = 0;
    Uint32 ulKeyClass = OBJ_CLASS_SECRET_KEY;


#ifndef _WIN32
    Uint8 kek_buf[KEK_SIZE] = { };
#else
    Uint8 kek_buf[KEK_SIZE] = { 0 };
#endif
    Uint32 kek_len = 0;

    Uint8 bWFile = FALSE;
    char *pWFile = 0;
    bool latest_fw = false;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        // key to wrap
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1)) {
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);
        }
        // private key file
        else if ((!bWFile) && (strcmp(argv[i], "-wk") == 0)
                 && (argc > i + 1)) {
            pWFile = argv[i + 1];
            bWFile = TRUE;
        }
        // wrapping key
        else if ((!bWrappingKey) && (strcmp(argv[i], "-w") == 0)
                 && (argc > i + 1)) {
            bWrappingKey = readLongIntegerArg(argv[i + 1], &ulWrappingKey);
        } else if ((strcmp(argv[i], "-m") == 0) && (argc > i + 1)) {
            (void) readIntegerArg(argv[i + 1], (Uint32 *) & ulMech);
            ulMech = get_wrap_mechanism(ulMech);
        } else if (!bFile && (strcmp(argv[i], "-out") == 0) &&
                   (argc > i + 1)) {
            KeyFile = argv[i + 1];
            bFile = 1;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Handle of key to export (-k) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bWrappingKey) {
        printf("\n\tError: Handle of wrapping Key (-w) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bFile) {
        printf("\n\tError: Key File (-out) is missing.\n");
        bHelp = TRUE;
    }
    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nExports a Symmetric key");
        printf("\n");
        printf
            ("\nSyntax: exSymKey -h -w <wrapping key> -k <key to export> -out <key file>\n");
        printf("                 [-m <wrapping mechanism>] [-wk <unwrapping key file>]\n");
        printf("\n");
        printf("\nWhere: -h   displays this information");
        printf("\n       -w   specifies the handle of the wrapping key");
        printf
            ("\n       -k   specifies the handle of the key to export:3DES/AES/RC4 key handle");
        printf
            ("\n       -m   specifies the wrapping mechanism (Optional)");
        printf("\n            NIST_AES_WRAP - 4");
        printf
            ("\n       -out specifies the file to write the exported key");
        printf
            ("\n       -wk  specifies the unwrapping key file if the unwrapping has to be done without the HSM");

        printf("\n");

        printf("\n");
        goto err;
    }

    if (bWFile) {
        ulRet = read_file((char *) pWFile, kek_buf, sizeof(kek_buf), &kek_len);
        if (kek_len != 16 && kek_len != 24 && kek_len != 32) {
            printf("\nInvalid file. Should be an AES key\n");
            ulRet = -1;
            goto err;
        }

    }


    ulTemp = 4;
    if ((ulRet = Cfm3GetAttribute(session_handle,
                                  ulKey,
                                  OBJ_ATTR_CLASS,
                                  (Uint8 *) & ulKeyClass, &ulTemp, NULL,
                                  NULL, NULL)) == 0) {
        ulKeyClass = atoi((Int8 *) & ulKeyClass);
        if (ulKeyClass != OBJ_CLASS_SECRET_KEY) {
            printf("\n\t%d is not a symmetric key\n", (int) ulKey);
            ulRet = ERR_INVALID_INPUT;
            goto err;
        }
    }

    pKey = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    pWrappedKey = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    if (!pKey || !pWrappedKey) {
        printf("Memory allocation failure\n");
        ulRet = -1;
        goto err;
    }
    ulKeyLen = ulWrappedKeyLen = BUFSIZE;

    ulRet = is_fw_newset_with_aes_nist_pad(session_handle,
                                           MAJOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           MINOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           BUILD_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           &latest_fw);
    if (ulRet)
        goto err;

    ulRet = set_iv_based_fw_ver(pIV, 8, true, latest_fw);
    if (ulRet)
        goto err;

    ulRet = Cfm3ExportWrapKey(session_handle,
                              ulWrappingKey,
                              ulKey, pIV, pWrappedKey,
                              &ulWrappedKeyLen, NULL, latest_fw);
    printf("\n\tCfm3ExportWrapKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet) {
        goto err;
    }

    if (!bWFile) {
        ulRet = Cfm3ExportUnwrapKey(session_handle,
                                    pWrappedKey,
                                    ulWrappedKeyLen,
                                    pKey,
                                    &ulKeyLen, ulWrappingKey,
                                    pIV, NULL, latest_fw);
        printf("\n\tCfm3ExportUnwrapKey returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        if (ulRet) {
            goto err;
        }
    } else {
        ulRet = unwrap_key_on_host(session_handle, ulWrappedKeyLen, pWrappedKey,
                                    kek_len, kek_buf, &ulKeyLen, pKey,
                                    latest_fw ? NULL : pIV,
                                    CRYPTO_MECH_AES_KEY_WRAP_PAD, latest_fw);
        if (ulRet) {
            printf("AES_unwrap_key failed\n");
            ulRet = -1;
            goto err;
        }
    }
    if (WriteBinaryFile(KeyFile, (char *) pKey, ulKeyLen))
        printf
            ("\n\nExported Symmetric Key written to file \"%s\"\n",
             KeyFile);
    else {
        printf("\n\nCouldn't write to file %s\n", KeyFile);
        ulRet = ERR_WRITE_OUTPUT_FILE;
    }

  err:
    if (pKey)
        free(pKey);
    if (pWrappedKey)
        free(pWrappedKey);
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : imSymKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 imSymKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    int k=0;
    Uint64 ulNewKey = 0;

    Uint64 randomIV = 0ULL;
    Uint8 *pIV = (Uint8 *) & randomIV;

    Uint8 bWrappingKeyHandle = FALSE;
    Uint64 ulWrappingKeyHandle = 0;

    Uint8 bKeyType = FALSE;
    Uint32 ulKeyType = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;
    Uint8 ucKeyLocation = STORAGE_FLASH;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulCount = 0;

    Uint8 bKey = FALSE;
    char *pTemp = NULL;

    Uint8 bAttest = FALSE;
    Uint8 *attestedResponse = NULL;
    Uint32 attestedLength = MTU_SIZE;

    Uint8 pKey[4096] = { 0 };
    Uint32 ulKeyLen = 0;

    Uint8 bMValue = FALSE;
    Uint8 ulMValue = 0;

    Uint8 bWFile = FALSE;
    char *pWFile = 0;
#ifndef _WIN32
    Uint8 kek_buf[KEK_SIZE] = { };
#else
    Uint8 kek_buf[KEK_SIZE] = { 0 };
#endif
    Uint32 kek_len = 0;

    Uint8 *pWrappedKey = NULL;
    Uint32 ulWrappedKeyLen = 0;
    Uint8 *pTemplate = NULL;
    Uint32 ulTemplateSz = 0, ulAtribCount = 0;

    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;
    bool latest_fw = false;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        // type
        else if ((!bKeyType) && (strcmp(argv[i], "-t") == 0)
                 && (argc > i + 1)) {
            bKeyType = readIntegerArg(argv[i + 1], &ulKeyType);
        }
        // wrapping key handle
        else if ((strcmp(argv[i], "-w") == 0) && (argc > i + 1))
            bWrappingKeyHandle =
                readLongIntegerArg(argv[i + 1], &ulWrappingKeyHandle);
        // label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);
        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            char *pTemp = NULL;
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulCount);
            if (pTemp)
                free(pTemp);
        }
        // private key file
        else if ((!bWFile) && (strcmp(argv[i], "-wk") == 0)
                 && (argc > i + 1)) {
            pWFile = argv[i + 1];
            bWFile = TRUE;
        } else if ((!bMValue) && (strcmp(argv[i], "-m_value") == 0)
                   && (argc > i + 1)) {
            ulMValue = atoi(argv[i + 1]);
            bMValue = TRUE;
            if (ulMValue > MAX_USERS_SHARED)
                bHelp = TRUE;
        }
        // wrapped key
        else if ((!bKey) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1)) {
            bKey = readFileArg(argv[i + 1], &pTemp, &ulKeyLen);
            if (bKey == TRUE && ulKeyLen <= sizeof(pKey))
                memcpy(&pKey[0], pTemp, ulKeyLen);
        } else if (strcmp(argv[i], "-sess") == 0) {
            ucKeyLocation = STORAGE_RAM;
            i--;                //This for loops skips i by 2. so go with it.
        } else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                   && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else if ((!bAttest) && (strcmp(argv[i], "-attest") == 0)
                   && (argc > i)) {
            bAttest = TRUE;
            i--;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKeyType) {
        printf("\n\tError: Key type (-t) is missing.\n");
        bHelp = TRUE;
    }
    // ensure that we have all the required args
    if (!bHelp && !bWrappingKeyHandle) {
        printf("\n\tError: wrapping key handle (-w) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bLabel) {
        printf("\n\tError: Key label (-l) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bKey) {
        printf("\n\tError: Key filename (-f) is missing.\n");
        bHelp = TRUE;
    }
    if (bTimeout && !bMinServers) {
        printf
            ("\n\tError: Minimum servers (-min_srv) option is missing\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nImports a symmetric key.");
        printf("\n");
        printf
            ("\nSyntax: imSymKey -h -l <label> -t <key type> -f <key file name> -w <wrapper key handle>\n");
        printf("\t\t\t[-u <user-ids>] [-sess] [-id <key ID>] [-m_value <0..8>]\n");
        printf("\t\t\t[-wk <wrapping key file>][-attest]\n");
        printf
            ("\t\t\t[-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf("\n       -l       specifies the new key's Label");
        printf("\n       -t       specifies the key type");
        printf
            ("\n                (16 = GENERIC_SECRET, 18 = RC4, 21 = DES3/DES, 31 = AES)");
        printf
            ("\n       -f       specifies the filename containing the key to import");
        printf("\n                For RC4,  file size <= 256 bytes\n");
        printf
            ("                    DES,  file size = 8 bytes (non-FIPS mode)\n");
        printf("                    DES3, file size = 24 bytes\n");
        printf("                    AES,  file size = 16, 24 and 32 bytes");
        printf
            ("\n       -w       specifies the wrapper key handle, 4 for KEK");
        printf
            ("\n       -u       specifies the list of users to share with (separated by ,) (optional)");
        printf("\n       -sess    specifies key as session key");
        printf
            ("\n       -attest  performs the attestation check on the firmware response");
        printf("\n       -id      specifies key ID");
        printf
            ("\n       -wk      specifies the wrapping key if the wrapping has to be done without the HSM");
        printf
            ("\n       -min_srv specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                (till the time specified by -timeout option)");
        printf
            ("\n                if the key fails to get synced on required number of servers, the key will be deleted");

        printf
            ("\n       -timeout specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }

    if (ulKeyType == 21)
        /*DES*/ {
        if ((fipsState < 2) && (ulKeyLen == 8)
            && (3 * ulKeyLen <= sizeof(pKey))) {
            memcpy(pKey + 8, pKey, 8);
            memcpy(pKey + 16, pKey, 8);
            ulKeyLen = 24;
        }
        }

    if (bWFile) {
        ulRet = read_file((char *) pWFile, kek_buf, sizeof(kek_buf), &kek_len);
        if (kek_len != 16 && kek_len != 24 && kek_len != 32) {
            printf("\nInvalid file. Should be an AES key\n");
            ulRet = -1;
            goto exit_error;
        }
    }

    pWrappedKey = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    ulWrappedKeyLen = BUFSIZE;
    pTemplate = (Uint8 *) CALLOC_WITH_CHECK(1, BUFSIZE);
    if (!pWrappedKey || !pTemplate) {
        printf("Memory allocation failure \n");
        ulRet = ERR_MEMORY_ALLOC_FAILURE;
        goto exit_error;
    }
    ulRet = is_fw_newset_with_aes_nist_pad(session_handle,
                                           MAJOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           MINOR_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           BUILD_FW_VER_SUPPORT_AES_WRAP_PAD,
                                           &latest_fw);
    if (ulRet)
        goto exit_error;

    ulRet = set_iv_based_fw_ver(pIV, 8, true, latest_fw);
    if (ulRet)
        goto exit_error;

    for (k=0;k<100;k++){
    if (!bWFile) {
        ulRet = Cfm3ImportWrapKey(session_handle,
                                  pKey,
                                  ulKeyLen,
                                  ulWrappingKeyHandle, pIV,
                                  pWrappedKey, &ulWrappedKeyLen, NULL,
                                  latest_fw);
        printf("\n\tCfm3ImportWrapKey returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
        if (ulRet) {
            goto error;
        }
    } else {
        ulRet = wrap_key_on_host(session_handle, ulKeyLen, pKey,
                                 kek_len, kek_buf,
                                 &ulWrappedKeyLen, pWrappedKey,
                                 (latest_fw == true) ? NULL : pIV,
                                 CRYPTO_MECH_AES_KEY_WRAP_PAD, latest_fw);
        if (ulRet) {
            printf("AES_wrap_key failed\n");
            ulRet = -1;
            goto error;
        }
    }

    ulRet = Cfm3CreateUnwrapTemplate(OBJ_CLASS_SECRET_KEY,
                                     ulKeyType,
                                     ucKeyLocation,
                                     pUsers, ulCount,
                                     ulMValue,
                                     (Uint8 *) pID, ulIDLen,
                                     (Uint8 *) pLabel, ulLabelLen,
                                     ulKeyLen,
                                     0,
                                     0,
                                     0,
                                     pTemplate,
                                     &ulTemplateSz, &ulAtribCount);

    printf("\n\tCfm3CreateUnwrapTemplate returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    if (ulRet) {
        goto error;
    }

    if (bAttest) {
        attestedResponse = (Uint8 *) CALLOC_WITH_CHECK(1, attestedLength);

        if (!attestedResponse) {
            printf("Memory allocation failure \n");
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto exit_error;
        }
    }

    /* unwrap the key on HSM */
    ulRet = Cfm3ImportUnWrapKey(session_handle,
                                pWrappedKey, ulWrappedKeyLen,
                                ulWrappingKeyHandle,
                                pIV,
                                pTemplate, ulTemplateSz,
                                ulAtribCount,
                                &ulNewKey,
                                attestedResponse, &attestedLength,
                                &request_id, ucKeyLocation, latest_fw);

    printf("\n\tCfm3ImportUnWrapKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    }
  error:
    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf("\n\tSymmetric Key Imported.  Key Handle: %llu \n",
               ulNewKey);
        if (bAttest) {
            if (attestedLength)
                if (verifyAttestation
                    (session_handle, (Uint8 *) attestedResponse,
                     attestedLength)) {
                    ulRet = ERR_ATTESTATION_CHECK;
                }
        }
    }
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet =
                Cfm3FindSingleKey(session_handle, ulNewKey, &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle, ulNewKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        } else
            printf("\n\tSymmetric Key Imported.  Key Handle: %llu \n",
                   ulNewKey);

    }

  exit_error:
    if (attestedResponse)
        free(attestedResponse);
    if (pWrappedKey)
        free(pWrappedKey);
    if (pTemplate)
        free(pTemplate);

    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : deleteKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 deleteKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;
    Uint32 request_id = -1;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // key handle
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Key handle (-k) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nDelete a key specifying a key handle.");
        printf("\n");
        printf("\nSyntax: deleteKey -h -k <key handle>\n");
        printf("\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -k  specifies the key handle to delete");
        printf("\n");
        return ulRet;
    }

    ulRet = Cfm3DeleteKey(session_handle, ulKey, &request_id);
    printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, NULL);
    }


    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : shareKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 shareKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulUserCount = 0;

    Uint8 bShare = FALSE;
    Uint8 share = 1;
    Uint32 request_id = -1;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // key handle
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);

        // unshare?
        else if ((!bShare) && (strcmp(argv[i], "-d") == 0)) {
            bShare = TRUE;
            share = 0;
            i--;
        }
        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            char *pTemp = NULL;
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulUserCount);
            if (pTemp)
                free(pTemp);
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Key handle (-k) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nShare a key specifying a key handle.");
        printf("\n");
        printf
            ("\nSyntax: shareKey -h -k <key handle> [-d] [-u <user id>] \n");
        printf("\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -k  specifies the key handle to share/unshare");
        printf("\n       -d  unshare a shared key with users/sessions");
        printf
            ("\n       -u  specifies the list of users to share/unshare with (separated by ,)");
        printf("\n");
        goto exit_error;
    }

    ulRet =
        Cfm3ShareKey(session_handle,
                     ulKey, share, pUsers, ulUserCount, &request_id);
    printf("\n\tCfm3ShareKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, NULL);
    }
  exit_error:

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : getKeyInfo
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 getKeyInfo(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulUserCount = MAX_USERS_SHARED;
    Uint8 ulMValue = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // key handle
        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Key handle (-k) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nShow key info specifying a key handle.");
        printf("\n");
        printf("\nSyntax: getKeyInfo -h -k <key handle> \n");
        printf("\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -k  specifies the key handle");
        printf("\n\n");
        return ulRet;
    }

    ulRet = Cfm3GetKeyInfo(session_handle,
                           ulKey, pUsers, &ulUserCount, &ulMValue, NULL);
    printf("\n\tCfm3GetKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    if (ulRet == RET_OK) {
        if (ulUserCount < 1) {
            printf("\n\tAlso, global Key, accessible by all users");
        } else {
            printf("\n\tOwned by user: %d\n", pUsers[0]);
            if (ulUserCount > 1)
                printf("\n\tShared with following %d user(s):",
                       ulUserCount - 1);
            for (i = 1; (i < ulUserCount) && (i < MAX_USERS_SHARED); i++)
                printf("\n\t\t %d", pUsers[i]);
        }
        if (ulMValue > 1) {
            printf
                ("\n\t %d Users need to approve to use/manage this key",
                 ulMValue);
        }
        if (ulMValue > ulUserCount)
            printf
                ("\n\t This key is unusable as M > N. Better delete this.");
        printf("\n");
    }
    printf("\n");

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : Error2String
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 Error2String(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bResponseCode = FALSE;
    Uint32 ulResponseCode = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // Response Code
        else if ((!bResponseCode) && (strcmp(argv[i], "-r") == 0)
                 && (argc > i + 1)) {
            bResponseCode = TRUE;
            ulResponseCode = strtoul(argv[i + 1], NULL, 0);
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bResponseCode) {
        printf("\n\tError: Response code (-r) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nconvert a response code to Error String.");
        printf("\n");
        printf("\nSyntax: Error2String -h -r <response code> \n");
        printf("\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -r  specifies response code to be converted");
        printf("\n");
        return ulRet;
    }

    printf("\n\tError Code %x maps to %s\n", ulResponseCode,
           Cfm2ResultAsString(ulResponseCode));

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : findSingleKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 findSingleKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKeyHandle = FALSE;
    Uint64 ulKeyHandle = -1;
    Uint32 request_id = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        else if ((!bKeyHandle) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1))
            bKeyHandle = readLongIntegerArg(argv[i + 1], &ulKeyHandle);
        else
            bHelp = TRUE;
    }

    if (bHelp || !bKeyHandle) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nChecks the existence of a key handle on all connected HSMs\n");
        printf("\n");
        printf("\nSyntax: findSingleKey -h -k <key handle>");
        printf("\n");
        printf("\nWhere: -h     displays this information");
        printf("\n       -k     specifies the key handle to search for");
        printf("\n");
        return ulRet;
    }
    /* TODO return proper errorr */
    ulRet = Cfm3FindSingleKey(session_handle, ulKeyHandle, &request_id);

    printf("\n\tCfm3FindSingleKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, NULL);
    }
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : findKey
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 findKey(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKeyClass = FALSE;
    Uint32 ulKeyClass = -1;

    Uint8 bKeyType = FALSE;
    Uint32 ulKeyType = -1;

    Uint8 bKeyLoc = FALSE;
    Uint8 ucKeyLocation = -1;

    Uint8 bUsers = FALSE;
    Uint16 pUsers[MAX_USERS_SHARED] = { 0 };
    Uint8 ulUserCount = 0;

    Uint8 bID = FALSE;
    char *pID = 0;
    Uint32 ulIDLen = 0;

    Uint8 bLabel = FALSE;
    char *pLabel = 0;
    Uint32 ulLabelLen = 0;

    Uint8 bModulus = FALSE;
    Uint8 *pModulus = 0;
    Uint32 ulModLen = 0;

    Uint8 bKeyCheckValue = FALSE;
    Uint8 *pKCV = NULL;
    Uint32 ulKCVLen = 0;

    Uint64 *pulKeyArray = 0;
    Uint32 ulKeyArrayLen = 0;

    Uint32 request_id = 0;

    int j = 0, found = 0;
    int k = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // class
        else if ((!bKeyClass) && (strcmp(argv[i], "-c") == 0)
                 && (argc > i + 1))
            bKeyClass = readIntegerArg(argv[i + 1], &ulKeyClass);

        // type
        else if ((!bKeyType) && (strcmp(argv[i], "-t") == 0)
                 && (argc > i + 1))
            bKeyType = readIntegerArg(argv[i + 1], &ulKeyType);

        // location
        else if ((!bKeyLoc) && (strcmp(argv[i], "-sess") == 0)
                 && (argc > i + 1)) {
            uint32_t tmp;
            bKeyLoc = readIntegerArg(argv[i + 1], &tmp);
            if (tmp == 1)
                ucKeyLocation = STORAGE_RAM;
            else if (tmp == 0)
                ucKeyLocation = STORAGE_FLASH;
            else
                bHelp = TRUE;
        }
        // label
        else if ((!bLabel) && (strcmp(argv[i], "-l") == 0)
                 && (argc > i + 1))
            bLabel = readArgAsString(argv[i + 1], &pLabel, &ulLabelLen);

        // Key ID
        else if ((!bID) && (strcmp(argv[i], "-id") == 0)
                 && (argc > i + 1))
            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);

        else if ((!bID) && (strcmp(argv[i], "-idx") == 0)
                 && (argc > i + 1)) {
            BIGNUM *bn = NULL;
            int len = 0;

            bID = readArgAsString(argv[i + 1], &pID, &ulIDLen);
            len = ulIDLen;

            if ((!strncmp(pID, "0x", 2)) || !(strncmp(pID, "0X", 2))) {
#ifndef _WIN32
                char buf[128] = { };
#else
                char buf[128] = { '\0' };
#endif
                char *ptr = NULL;

                ptr = pID + 2;

                if (n3fips_strncpy
                    (buf, ptr, 128,
                     (ulIDLen - 2) >= 128 ? 127 : (ulIDLen - 2))) {
                    printf("Error copying string\n");
                    goto exit;
                }
                memset(pID, 0, len);
                if (n3fips_strncpy(pID, buf, len, ulIDLen - 2)) {
                    printf("Error copying string\n");
                    goto exit;
                }
                len = len - 2;
            }

            bn = BN_new();

            BN_hex2bn(&bn, pID);
            memset(pID, 0, len);

            BN_bn2bin(bn, (unsigned char *) pID);
            ulIDLen = len / 2;
            BN_free(bn);
        }
        // sharing
        else if ((!bUsers) && (strcmp(argv[i], "-u") == 0)
                 && (argc > i + 1)) {
            char *pTemp = NULL;
            Uint32 ulTempLen = 0;
            bUsers = readArgAsString(argv[i + 1], &pTemp, &ulTempLen);
            read_user_ids_from_string(pTemp, pUsers, &ulUserCount);
            if (pTemp)
                free(pTemp);
        } else if ((!bModulus) && (strcmp(argv[i], "-m") == 0)
                   && (argc > i + 1)) {
            BIGNUM *n = NULL;
            bModulus =
                readFileArg(argv[i + 1], (char **) &pModulus, &ulModLen);
            n = BN_new();
            BN_hex2bn(&n, (char *) pModulus);
            ulModLen = BN_num_bytes(n);
            BN_bn2bin(n, pModulus);
            BN_free(n);

            if (!bModulus) {
                ulRet = FALSE;
                goto exit;
            }
        } else if ((!bKeyCheckValue) && (strcmp(argv[i], "-kcv") == 0)
		   && (argc > i + 1)) {
            BIGNUM *bn = NULL;
	    bKeyCheckValue =
		    readArgAsString(argv[i + 1], (char **) &pKCV, &ulKCVLen);
	    bn = BN_new();
	    if ((!strncmp((char *) pKCV, "0x", 2)) ||
		!(strncmp((char *) pKCV, "0X", 2))) {
		BN_hex2bn(&bn, (char *) pKCV + 2);
	    } else {
		BN_hex2bn(&bn, (char *) pKCV);
	    }
	    ulKCVLen = BN_num_bytes(bn);
            BN_bn2bin(bn, pKCV);
	    BN_free(bn);
	} else
            bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nFind keys optionally matching the specified key class, key label and modulus.");
        printf("\n");
        printf("\nSyntax: findKey -h [-c <key class>] [-t <key type>]"
               "\n\t\t [-l <key label>] [-id <key ID>] [-idx <key ID in hex>]"
               "\n\t\t [-sess 0/1] [-u <user-ids>] "
               "\n\t\t [-m <modulus>] [-kcv <kcv in hex>]");
        printf("\n");
        printf("\nWhere: -h     displays this information");
        printf("\n       -c     specifies the key class to find (optional)"
               "\n              2 = public"
               "\n              3 = private" "\n              4 = secret");
        printf("\n       -t     specifies the key type to find (optional)"
               "\n              0  = RSA"
               "\n              1  = DSA"
               "\n              3  = EC"
               "\n              16 = GENERIC_SECRET"
               "\n              18 = RC4"
               "\n              21 = DES3" "\n              31 = AES");
        printf
            ("\n       -l     specifies the key label to find (optional)");
        printf("\n       -id    specifies key ID (optional)");
        printf("\n       -idx   specifies key ID in Hex (optional)");
        printf
            ("\n       -sess  specifies option to find only session keys(1) "
             "or only token keys(0) (optional)");
        printf
            ("\n       -u     specifies the list of users shared with (separated by ,) (optional)");
        printf
            ("\n       -m     specifies the binary file containing RSA modulus to match with (optional)");
        printf
            ("\n       -kcv   specifies the Key Check Value to be searched for (optional)");
        printf("\n");
        goto exit;
    }

    ulKeyArrayLen = 0;
    ulRet = Cfm3FindKey(session_handle,
                        j, ulKeyClass, ulKeyType,
                        ucKeyLocation,
                        (Uint16 *) pUsers, ulUserCount,
                        (Uint8 *) pID, ulIDLen + 1,
                        (Uint8 *) pLabel, ulLabelLen + 1,
                        (Uint8 *) pModulus, ulModLen,
                        pKCV, ulKCVLen,
                        NULL, &ulKeyArrayLen, &request_id);

    if (ulRet != RET_OK) {
        goto end;
    }

    printf("\n\tTotal number of keys present: %u\n", ulKeyArrayLen);

    if (ulKeyArrayLen > 0) {
        pulKeyArray = (Uint64 *) calloc(ulKeyArrayLen, sizeof(Uint64));
        if (pulKeyArray == 0) {
            ulRet = ERR_MEMORY_ALLOC_FAILURE;
            goto end;
        }

        ulRet = Cfm3FindKey(session_handle,
                            j, ulKeyClass, ulKeyType,
                            ucKeyLocation,
                            (Uint16 *) pUsers, ulUserCount,
                            (Uint8 *) pID, ulIDLen + 1,
                            (Uint8 *) pLabel, ulLabelLen + 1,
                            (Uint8 *) pModulus, ulModLen,
                            pKCV, ulKCVLen,
                            pulKeyArray, &ulKeyArrayLen, &request_id);

        if (ulRet == 0 || ulRet == RET_RESULT_SIZE) {
            if (ulKeyArrayLen != 0) {
                Uint64 ulValue = 0;
                printf
                    ("\n\tNumber of matching keys from start index %d::%d\n",
                     j, ulKeyArrayLen + j - 1);
                printf("\n\tHandles of matching keys:\n\t");
                for (i = 0; i < ulKeyArrayLen - 1; i++) {
                    ulValue = (pulKeyArray[i]);
                    if (ulValue) {
                        printf("%llu, ", ulValue);
                        k++;
                        if (0 == ((i + 1) % 15))
                            printf("\n\t");
                    }

                }
                ulValue = (pulKeyArray[i]);
                if (ulValue) {
                    printf("%llu\n", ulValue);
                    k++;
                }

                found += ulKeyArrayLen;

                j = found;

            } else {
                printf("\n\tNo more keys are found\n");
            }
        } else {
            printf
                ("\n\tFailed to fetch the keys with error %x : %s\n",
                 ulRet, Cfm2ResultAsString(ulRet));
        }
    }

end:
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, NULL);
    }

    printf("\n\tCfm3FindKey returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
exit:
    if (pulKeyArray)
        free(pulKeyArray);
    if (pLabel)
        free(pLabel);
    if (pID)
        free(pID);

    return ulRet;
}

Uint32 dumpAttribute(char *fileName, Uint8 * attr, Uint32 attrLength,
                     char *attrString)
{

    FILE *fp;
    int type = 0, size = 0, cnt = 0, i;
    Attribute *attribute;
    Uint8 *value = NULL;

    if (!attrString || !attr) {
        printf("Invalid buffers\n ");
        return ERR_INVALID_ARGUMENTS;
    }

    fp = fopen(fileName, "w+");
    if (fp == NULL) {
        printf("Failed to open file\n ");
        return ERR_OPEN_FILE;
    }

    if (!strcmp(attrString, "OBJ_ATTR_ALL")) {

        Object *obj = (Object *) attr;
        printf("\nAttribute size: %d, count: %d\n",
               attrLength, betoh32(obj->attr_count));
        cnt = betoh32(obj->attr_count);
        attribute = (Attribute *) ((Uint8 *) obj + sizeof(Object));
        for (i = 1; i <= cnt; i++) {
            type = betoh32(attribute->type);
            size = betoh32(attribute->size);
            value = attribute->value;

            if (type == OBJ_ATTR_MODULUS)
                cavium_dump_file(fp, getAttributeString(type), value,
                                 size);
            else if ((type == OBJ_ATTR_LABEL) || (type == OBJ_ATTR_ID))
                cavium_dump_str_file(fp, getAttributeString(type), value,
                                     size);
            else
                cavium_dump_int_file(fp, getAttributeString(type), value,
                                     size);
            attribute =
                (Attribute *) ((Uint8 *) attribute + sizeof(Attribute) +
                               betoh32(attribute->size));
        }
    } else {
        if (!strcmp(attrString, "OBJ_ATTR_MODULUS"))
            cavium_dump_file(fp, attrString, attr, attrLength);
        else if (!
                 (strcmp(attrString, "OBJ_ATTR_LABEL")
                  && strcmp(attrString, "OBJ_ATTR_ID")))
            cavium_dump_str_file(fp, attrString, attr, attrLength);
        else if (!strcmp(attrString, "OBJ_ATTR_PUBLIC_EXPONENT") ||
                 !strcmp(attrString, "OBJ_ATTR_KCV"))
            cavium_dump_int_file(fp, attrString, attr, attrLength);
        else
            cavium_dump_str_to_hex_file(fp, attrString, attr);
    }

    printf("Written to: %s file\n", fileName);

    fclose(fp);
    return RET_OK;
}

/****************************************************************************
 *
 * FUNCTION     : getAttribute
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 getAttribute(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bFile = FALSE;
    char *AttrFile = NULL;

    Uint8 bAttribute = FALSE;
    Uint32 ulAttribute = 0;

    Uint8 *pAttr = 0;
    Uint32 ulAttrLen = MTU_SIZE;

    Uint8 bAttest = FALSE;
    Uint8 *attestedResponse = NULL;
    Uint32 attestedLength = MTU_SIZE;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // key
        else if ((!bKey) && (strcmp(argv[i], "-o") == 0)
                 && (argc > i + 1)) {
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);
        }
        // attribute
        else if ((!bAttribute) && (strcmp(argv[i], "-a") == 0)
                 && (argc > i + 1))
            bAttribute = readIntegerArg(argv[i + 1], &ulAttribute);

        else if ((!bFile) && (strcmp(argv[i], "-out") == 0)
                 && (argc > i + 1)) {
            AttrFile = argv[i + 1];
            bFile = 1;
        } else if ((!bAttest) && (strcmp(argv[i], "-attest") == 0)
                   && (argc > i)) {
            bAttest = TRUE;
            i--;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Object handle (-o) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bAttribute) {
        printf("\n\tError: Attribute ID (-a) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bFile) {
        printf("\n\tError: Attribute File (-out) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nGet an attribute from an object.");
        printf("\n");
        printf
            ("\nSyntax: getAttribute -h -o <object Handle> -a <attribute> -out <attribute file> [-attest]");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf("\n       -o       specifies the object handle");
        printf
            ("\n       -a       specifies the attribute to read.(512 for all attributes)");
        printf
            ("\n       -out     specifies the file to write the attribute value");

        printf
            ("\n       -attest  performs the attestation check on the firmware response\n");
        printf
            ("\n       (run listAttributes to see a list of all possible attribute values)");
        printf("\n\n");
        goto exit;
    }

    if (bAttest) {
        attestedResponse = (Uint8 *) CALLOC_WITH_CHECK(1, MTU_SIZE);
    }

    ulRet = Cfm3GetAttribute(session_handle,
                             ulKey, ulAttribute, 0, &ulAttrLen,
                             attestedResponse, &attestedLength, NULL);

    if ( ((RET_OK != ulRet) && (RET_RESULT_SIZE != ulRet)) ) {
        goto error;
    } else {
        ulRet = RET_OK;
    }

    if (bAttest) {
        if (attestedLength)
            if (verifyAttestation
                (session_handle, (Uint8 *) attestedResponse,
                 attestedLength)) {
                ulRet = ERR_ATTESTATION_CHECK;
            }
        memset(attestedResponse, 0, MTU_SIZE);
        attestedLength = MTU_SIZE;
        ulAttrLen += RSA_2048_SIGN_SIZE;        //Add 256 bytes for signature
    }

    if (!(ulRet) && ulAttrLen) {
        pAttr = (Uint8 *) CALLOC_WITH_CHECK(1, ulAttrLen);
        print_debug("Attribute length %d\n", ulAttrLen);

        ulRet = Cfm3GetAttribute(session_handle,
                                 ulKey, ulAttribute, pAttr, &ulAttrLen,
                                 attestedResponse, &attestedLength, NULL);
        if (!ulRet) {
            if (bAttest) {
                printf("\n\t Verifying attestation for value\n");
                if (verifyAttestation
                    (session_handle, (Uint8 *) attestedResponse,
                     attestedLength)) {
                    ulRet = ERR_ATTESTATION_CHECK;
                    goto error;
                }
            }
            ulRet =
                dumpAttribute(AttrFile, pAttr, ulAttrLen,
                              (char *) getAttributeString(ulAttribute));
        }
    }
  error:
    printf("\n\tCfm3GetAttribute returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

  exit:
    if (pAttr)
        free(pAttr);

    if (attestedResponse)
        free(attestedResponse);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : setAttribute
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 setAttribute(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bAttribute = FALSE;
    Uint32 ulAttribute = 0;

    Uint8 *pAttribute = 0;
    Uint32 ulAttributeLen = 0;
    Uint32 request_id = -1;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // key
        else if ((!bKey) && (strcmp(argv[i], "-o") == 0)
                 && (argc > i + 1)) {
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);
        }
        // attribute
        else if ((!bAttribute) && (strcmp(argv[i], "-a") == 0)
                 && (argc > i + 1))
            bAttribute = readIntegerArg(argv[i + 1], &ulAttribute);

        else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Object handle (-o) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bAttribute) {
        printf("\n\tError: Attribute ID (-a) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nSet an attribute value for an object.");
        printf("\n");
        printf
            ("\nSyntax: setAttribute -h -o <object handle> -a <attribute> \n");
        printf("\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -o  specifies the Object Handle");
        printf("\n       -a  specifies the Attribute to set");
        printf
            ("\n           (only the following attribute's value can be modified)");
        printf("\n           OBJ_ATTR_TOKEN                  = %d",
               0x00000001);

#if 0
	printf("\n           OBJ_ATTR_TRUSTED                = %d",
	       OBJ_ATTR_TRUSTED);
        printf("\n           OBJ_ATTR_LABEL                  = %d",
               0x00000003);
        printf("\n           OBJ_ATTR_ENCRYPT                = %d",
               0x00000104);
        printf("\n           OBJ_ATTR_DECRYPT                = %d",
               0x00000105);
        printf("\n           OBJ_ATTR_WRAP                   = %d",
               0x00000106);
        printf("\n           OBJ_ATTR_UNWRAP                 = %d",
               0x00000107);
	printf("\n           OBJ_ATTR_DESTROYABLE            = %d",
	       OBJ_ATTR_DESTROYABLE);
	printf("\n           OBJ_ATTR_WRAP_WITH_TRUSTED      = %d",
	       OBJ_ATTR_WRAP_WITH_TRUSTED);
#endif

        printf("\n\n");
        goto error;
    }

    ulRet = getAttributeValue(ulAttribute, &pAttribute, &ulAttributeLen);
    if (ulRet == 0)
        ulRet = Cfm3SetAttribute(session_handle,
                                 ulKey, ulAttribute, pAttribute,
                                 ulAttributeLen, &request_id);
    printf("\n\tCfm3SetAttribute returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, NULL);
    }

  error:
    if (pAttribute)
        free(pAttribute);

    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : listAttributes
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 listAttributes(int argc, char **argv)
{
    printf("\n");
    printf("\nDescription");
    printf("\n===========");
    printf
        ("\nThe following are all of the possible attribute values for getAttributes.");
    printf("\n");
    printf("\n      OBJ_ATTR_CLASS                  = %d", OBJ_ATTR_CLASS);
    printf("\n      OBJ_ATTR_TOKEN                  = %d", OBJ_ATTR_TOKEN);
    printf("\n      OBJ_ATTR_PRIVATE                = %d",
           OBJ_ATTR_PRIVATE);
    printf("\n      OBJ_ATTR_LABEL                  = %d", OBJ_ATTR_LABEL);
    printf("\n      OBJ_ATTR_TRUSTED                = %d", OBJ_ATTR_TRUSTED);
    printf("\n      OBJ_ATTR_KEY_TYPE               = %d",
           OBJ_ATTR_KEY_TYPE);
    printf("\n      OBJ_ATTR_ID                     = %d", OBJ_ATTR_ID);
    printf("\n      OBJ_ATTR_SENSITIVE              = %d",
           OBJ_ATTR_SENSITIVE);
    printf("\n      OBJ_ATTR_ENCRYPT                = %d",
           OBJ_ATTR_ENCRYPT);
    printf("\n      OBJ_ATTR_DECRYPT                = %d",
           OBJ_ATTR_DECRYPT);
    printf("\n      OBJ_ATTR_WRAP                   = %d", OBJ_ATTR_WRAP);
    printf("\n      OBJ_ATTR_UNWRAP                 = %d",
           OBJ_ATTR_UNWRAP);
    printf("\n      OBJ_ATTR_SIGN                   = %d", OBJ_ATTR_SIGN);
    printf("\n      OBJ_ATTR_VERIFY                 = %d",
           OBJ_ATTR_VERIFY);
    printf("\n      OBJ_ATTR_LOCAL                  = %d", OBJ_ATTR_LOCAL);
    printf("\n      OBJ_ATTR_MODULUS                = %d",
           OBJ_ATTR_MODULUS);
    printf("\n      OBJ_ATTR_MODULUS_BITS           = %d",
           OBJ_ATTR_MODULUS_BITS);
    printf("\n      OBJ_ATTR_PUBLIC_EXPONENT        = %d",
           OBJ_ATTR_PUBLIC_EXPONENT);
    //printf("\n      OBJ_ATTR_COEFFICIENT            = %d", OBJ_ATTR_COEFFICIENT);
    //printf("\n      OBJ_ATTR_VALUE_BITS             = %d", OBJ_ATTR_VALUE_BITS);
    printf("\n      OBJ_ATTR_VALUE_LEN              = %d",
           OBJ_ATTR_VALUE_LEN);
    printf("\n      OBJ_ATTR_EXTRACTABLE            = %d",
           OBJ_ATTR_EXTRACTABLE);
    //printf("\n      OBJ_ATTR_LOCAL                  = %d", OBJ_ATTR_LOCAL);
    printf("\n      OBJ_ATTR_NEVER_EXTRACTABLE      = %d", OBJ_ATTR_NEVER_EXTRACTABLE);
    printf("\n      OBJ_ATTR_ALWAYS_SENSITIVE       = %d", OBJ_ATTR_ALWAYS_SENSITIVE);
    //printf("\n      OBJ_ATTR_MODIFIABLE             = %d", OBJ_ATTR_MODIFIABLE);
    printf("\n      OBJ_ATTR_DESTROYABLE            = %d", OBJ_ATTR_DESTROYABLE);
    printf("\n      OBJ_ATTR_KCV                    = %d", OBJ_ATTR_KCV);
    printf("\n      OBJ_ATTR_WRAP_WITH_TRUSTED      = %d",
	   OBJ_ATTR_WRAP_WITH_TRUSTED);
    printf("\n\n");
    return 0;
}

/****************************************************************************
 *
 * FUNCTION     : insertMaskedObject
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 insertMaskedObject(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bFile = FALSE;
    char *pFile = 0;
    Uint32 ulFileLen = 0;

    Uint64 ulKey = 0;
    Uint8 bMinServers = FALSE;
    Uint8 ucMinServers = 0;

    Uint8 bTimeout = FALSE;
    Uint32 ulTimeoutValue = 0;
    Uint32 success_count = 0;
    Uint32 request_id = -1;



    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0) {
            bHelp = TRUE;

            // file
        } else if ((!bFile) && (strcmp(argv[i], "-f") == 0)
                   && (argc > i + 1)) {
            bFile = readFileArg(argv[i + 1], &pFile, &ulFileLen);
        } else if ((!bMinServers) && (strcmp(argv[i], "-min_srv") == 0)
                   && (argc > i + 1)) {
            ucMinServers = atoi(argv[i + 1]);
            bMinServers = TRUE;
            if (ucMinServers > MAX_CLUSTER_SIZE)
                bHelp = TRUE;
        }

        else if ((!bTimeout) && (strcmp(argv[i], "-timeout") == 0)
                 && (argc > i + 1)) {
            ulTimeoutValue = atoi(argv[i + 1]);
            bTimeout = TRUE;
        } else
            bHelp = TRUE;
    }

    // ensure that we have all the required args
    if (!bHelp && !bFile) {
        printf("\n\tError: File name (-f) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nInserts a masked object.");
        printf("\n");
        printf("\nSyntax: insertMaskedObject -h -f <filename> \n");
        printf
            ("\t\t\t   [-min_srv <minimum number of servers>] [-timeout <number of seconds>]\n");
        printf("\n");
        printf("\nWhere: -h       displays this information");
        printf
            ("\n       -f       specifies the file containing the masked key");
        printf
            ("\n       -min_srv specifies the number of servers the key should atleast be generated on or poll till it gets generated");
        printf("\n                (till the time specified by -timeout option)");
        printf
            ("\n                if the key fails to get synced on required number of servers, the key will be deleted");
        printf
            ("\n       -timeout specifies the number of seconds to wait for the key to get synced when min_srv option is used.");
        printf("\n                If nothing is specified, the polling will continue forever\n");
        printf("\n");
        goto exit_error;
    }

    ulRet = Cfm3InsertMaskedObject(session_handle,
                                   &ulKey, (Uint8 *) pFile, ulFileLen,
                                   &request_id);
    printf("\n\tCfm3InsertMaskedObject returned: 0x%02x %s%s\n", ulRet,
           ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    if (ulRet == 0 || ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        printf("\tNew Key Handle: %llu \n", ulKey);
    }
    /* Dont print cluster info if it is liquidsecurity error code */
    if (liquidsecurity_error_code(ulRet))
        request_id = -1;

    if (request_id != -1) {
        print_cluster_error(request_id, &success_count);
    }
    if (RET_OK == ulRet && success_count < ucMinServers) {
        printf
            ("\n Not a valid min_srv count, please check the number of servers in cluster !!");
        printf
            ("\n Key generation succesful in all servers %d present in the cluster\n",
             success_count);

    }
    /* print error info */
    if (ulRet == RET_CLUSTER_OPERATION_INCOMPLETE) {
        Uint32 time_taken = 0;
        while (ucMinServers) {
            if (success_count >= ucMinServers ||
                ((ulTimeoutValue != 0) && (time_taken > ulTimeoutValue)))
                break;
            sleep(1);
            printf("\n\tChecking key status (%d seconds)..\n",
                   time_taken++);
            ulRet = Cfm3FindSingleKey(session_handle, ulKey, &request_id);
            if (request_id != -1) {
                print_cluster_error(request_id, &success_count);
            } else {
                printf("\n\tChecking key status failed\n");
                printf("\n\tCfm3FindSingleKey returned : 0x%02x : %s\n",
                       ulRet, Cfm2ResultAsString(ulRet));
            }
        }
        if (success_count < ucMinServers) {
            printf("Couldn't verify key sync on %d servers\n",
                   ucMinServers);
            printf("Rolling back\n");
            ulRet = Cfm3DeleteKey(session_handle, ulKey, &request_id);
            printf("\n\tCfm3DeleteKey returned: 0x%02x %s%s\n",
                   ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));
            if (request_id != -1)
                print_cluster_error(request_id, NULL);
        } else
            printf("\tNew Key Handle: %llu \n", ulKey);
    }


  exit_error:
    return ulRet;
}

/****************************************************************************
 *
 * FUNCTION     : extractMaskedObject
 *
 * DESCRIPTION  :
 *
 * PARAMETERS   :
 *
 *****************************************************************************/
Uint32 extractMaskedObject(int argc, char **argv)
{
    Uint32 ulRet = 0;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bFile = FALSE;
    char *ObjFile = NULL;

    Uint8 DataBuffer[6000];
    Uint8 *pData = (Uint8 *) DataBuffer;
    Uint32 ulDataLen = sizeof(DataBuffer);


    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // object
        else if ((!bKey) && (strcmp(argv[i], "-o") == 0)
                 && (argc > i + 1)) {
            bKey = readLongIntegerArg(argv[i + 1], &ulKey);
        } else if ((!bFile) && (strcmp(argv[i], "-out") == 0) &&
                   (argc > i + 1)) {
            ObjFile = argv[i + 1];
            bFile = TRUE;
        } else
            bHelp = TRUE;

    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Object handle (-o) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bFile) {
        printf("\n\tError: Masked Object File (-out) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nExtracts a masked object.");
        printf("\n");
        printf
            ("\nSyntax: extractMaskedObject -h -o <object handle> -out <masked object file>\n");
        printf("\n");
        printf("\nWhere: -h    displays this information");
        printf("\n       -o    specifies the object handle to mask");
        printf
            ("\n       -out  specifies the file to write the masked object");
        printf("\n\n");

        return ulRet;
    }

    ulRet = Cfm3ExtractMaskedObject(session_handle,
                                    ulKey, (Uint8 *) pData, &ulDataLen,
                                    NULL);
    if (ulRet == 0) {
        if (WriteBinaryFile(ObjFile, (char *) pData, ulDataLen))
            printf
                ("\n\tObject was masked and written to file \"%s\" \n",
                 ObjFile);
        else {
            ulRet = ERR_WRITE_OUTPUT_FILE;
            printf("\n\tFailed to write masked object to a file. \n");
        }
    }
    printf("\n\tCfm3ExtractMaskedObject returned: 0x%02x %s%s\n",
           ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    return ulRet;
}


/*****************************************************************************
 *
 * FUNCTION     : getCaviumPrivKey
 *
 * DESCRIPTION  : Returns private key file in PEM format for given private key handle
 *
 * PARAMETERS   : input:   Keyhandle
 *                         file name to which private key is to be written
 *
 *                output:  Returns  non-zero on Error
 *                                  0 on Success
 *
 ******************************************************************************/
Uint32 getCaviumPrivKey(int argc, char **argv)
{
    Uint32 ulRet = -1;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;
    RSA *rsa = NULL;

    Uint8 bKey = FALSE;
    Uint64 ulKey = 0;

    Uint8 bFile = FALSE;
    char *KeyFile = NULL;

    Uint32 pubExpVal = 0;
    Uint32 ulpubExpValLen = 0;

    Uint32 ulModLen;
    Uint32 *temp = NULL;
    Uint8 *privexp = NULL;
    Uint8 *pModulus = NULL;
    Uint32 ulKeyType = 0;
    Uint32 key_class = 0;
    Uint32 attr_len = sizeof(ulKeyType);
    FILE *fd = NULL;

    Uint32 ulCurveID = 0;
    Uint32 ulCurveIDLen = 0;
    BN_CTX *ctx = NULL;
    EC_GROUP *group = NULL;
    BIGNUM *prime_bn = NULL, *priv_key = NULL;
    EC_KEY *eckey = NULL;
    EC_POINT *pub_key = NULL;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        else if ((!bKey) && (strcmp(argv[i], "-k") == 0)
                 && (argc > i + 1)) {
            bKey = TRUE;
            ulKey = strtoul(argv[i + 1], NULL, 0);
        } else if ((!bFile) && (strcmp(argv[i], "-out") == 0) &&
                   (argc > i + 1)) {
            KeyFile = argv[i + 1];
            bFile = TRUE;
        }

        else
            bHelp = TRUE;

    }

    // ensure that we have all the required args
    if (!bHelp && !bKey) {
        printf("\n\tError: Key handle (-k) is missing.\n");
        bHelp = TRUE;
    }
    if (!bHelp && !bFile) {
        printf("\n\tError: Key File (-out) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nCreates PrivateKey file for specified RSA or ECDSA private key handle.");
        printf("\n");
        printf
            ("\nSyntax:  getCaviumPrivKey -h -k <key handle> -out <key file>");
        printf("\n\n");
        printf("\nWhere: -h    displays this information");
        printf("\n       -k    specifies the RSA or ECDSA private key handle");
        printf
            ("\n       -out  specifies the file to write fake private key");
        printf("\n");
        return ulRet;
    }

    fd = fopen(KeyFile, "w");
    if (!fd) {
        printf("\n\tFailed to open file for writing\n");
        goto err;
    }

    /* get key type from key handle */
    if ((ulRet = Cfm3GetAttribute(session_handle,
                                  ulKey,
                                  OBJ_ATTR_KEY_TYPE,
                                  (Uint8 *) & ulKeyType, &attr_len, NULL,
                                  NULL, NULL))) {
        printf("\n\tFailed to get key attribute\n");
        goto err;
    }

    attr_len = sizeof(key_class);

    /* get private attribute from key handle */
    if ((ulRet = Cfm3GetAttribute(session_handle,
                                  ulKey,
                                  OBJ_ATTR_CLASS,
                                  (Uint8 *) & key_class, &attr_len, NULL,
                                  NULL, NULL))) {
        printf("\n\tFailed to get key attribute\n");
        goto err;
    }

    ulKeyType = atoi((char *) &ulKeyType);
    key_class = atoi((char *) &key_class);

    if (((ulKeyType != KEY_TYPE_RSA) && (ulKeyType != KEY_TYPE_ECDSA)) ||
            (key_class != OBJ_CLASS_PRIVATE_KEY)) {
        printf("\n\tInput key handle should be RSA/ECDSA private key handle\n");
        ulRet = ERR_KEY_HANDLE_INVALID;
        goto err;
    }

    /* get modulus length from private key */
    if ((ulRet = Cfm3GetAttribute(session_handle,
                    ulKey, OBJ_ATTR_MODULUS, NULL,
                    &ulModLen, NULL, NULL, NULL))) {
        printf("\n\tFailed to get key attribute\n");
        goto err;
    }

    pModulus = n3fips_calloc(ulModLen);
    if(!pModulus) {
        printf("\n\tFailed to allocate memory\n");
        goto err;
    }

    /* get modulus from private key */
    if ((ulRet = Cfm3GetAttribute(session_handle,
                    ulKey,
                    OBJ_ATTR_MODULUS, pModulus, &ulModLen,
                    NULL, NULL, NULL))) {
        printf("\n\tFailed to get key attribute\n");
        goto err;
    }

    if (ulKeyType == KEY_TYPE_RSA) {

        ulpubExpValLen = sizeof(pubExpVal);

        /* get public exponent from private key */
        if ((ulRet = Cfm3GetAttribute(session_handle,
                        ulKey,
                        OBJ_ATTR_PUBLIC_EXPONENT,
                        (Uint8 *) & pubExpVal, &ulpubExpValLen,
                        NULL, NULL, NULL))) {
            printf("\n\tFailed to get key attribute\n");
            goto err;
        }

        rsa = RSA_new();

        if (!rsa->n && ((rsa->n = BN_new()) == NULL))
            goto err;
        if (!rsa->d && ((rsa->d = BN_new()) == NULL))
            goto err;
        if (!rsa->e && ((rsa->e = BN_new()) == NULL))
            goto err;
        if (!rsa->p && ((rsa->p = BN_new()) == NULL))
            goto err;
        if (!rsa->q && ((rsa->q = BN_new()) == NULL))
            goto err;
        if (!rsa->dmp1 && ((rsa->dmp1 = BN_new()) == NULL))
            goto err;
        if (!rsa->dmq1 && ((rsa->dmq1 = BN_new()) == NULL))
            goto err;
        if (!rsa->iqmp && ((rsa->iqmp = BN_new()) == NULL))
            goto err;

        /* Modulus */
        if (!BN_bin2bn(pModulus, ulModLen, rsa->n)) {
            printf("\n\tBN_bin2bn failed\n");
            goto err;
        }

        /* Public  Exponent */
        if (!BN_bin2bn((Uint8 *) & pubExpVal, ulpubExpValLen, rsa->e)) {
            printf("\n\tBN_bin2bn failed\n");
            goto err;
        }

        privexp = OPENSSL_malloc(ulModLen);
        temp = (Uint32 *) privexp;
        for (i = 0; i < ulModLen / 4; i++, temp++)
            *temp = CAV_SIG_HSM_KEY;

        memset(&(privexp[8]), 0, 8);
        memcpy(&(privexp[8]), (Uint8 *) & ulKey, 8);

        /* Private Exponent */
        BN_bin2bn(privexp, ulModLen, rsa->d);

        /* Turn off delete key handle flag in RSA flags, */
        /* so RSA_free does not delete the key handle from card */
        rsa->flags &= 0xbfff;

        if (!PEM_write_RSAPrivateKey(fd, rsa, NULL, NULL, 0, NULL, NULL)) {
            printf("\n\tPEM_write_RSAPrivateKey failed\n");
            goto err;
        }
    } else {
        ulCurveIDLen = sizeof(ulCurveID);
        /* get curve ID from private key */
        if ((ulRet = Cfm3GetAttribute(session_handle,
                        ulKey,
                        OBJ_ATTR_MODULUS_BITS,
                        (Uint8 *) & ulCurveID, &ulCurveIDLen,
                        NULL, NULL, NULL))) {
            printf("\n\tFailed to get key attribute\n");
            goto err;
        }
        ulCurveID = atoi((char *) &ulCurveID);

        group = EC_GROUP_new_by_curve_name(ulCurveID);
        if (group == NULL) {
            printf("\n\tUnable to create curve id %d\n", ulCurveID);
            goto err;
        }

        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        EC_GROUP_set_point_conversion_form(group,
                POINT_CONVERSION_UNCOMPRESSED);

        eckey = EC_KEY_new();
        if (eckey == NULL) {
            printf("Failed to create ec key\n");
            goto err;
        }

        if (EC_KEY_set_group(eckey, group) == 0) {
            printf("Unable to set the group (%d)\n", ulCurveID);
            goto err;
        }
        pub_key = EC_POINT_new(EC_KEY_get0_group(eckey));
        if (pub_key == NULL) {
            printf("\n\tEC_POINT_new failed\n");
            goto err;
        }

        EC_POINT_oct2point(group, pub_key, pModulus,
                ulModLen, NULL);
        EC_KEY_set_public_key(eckey, (const EC_POINT *)
                pub_key);

        ctx = BN_CTX_new();
        prime_bn = BN_CTX_get(ctx);
        if (!EC_GROUP_get_curve_GFp(group, prime_bn, NULL, NULL, ctx)) {
            printf("\n\tEC_GROUP_get_curve_GFp failed\n");
            goto err;
        }
        ulModLen = BN_num_bytes(prime_bn);
        ulModLen = ROUNDUP8(ulModLen);

        privexp = OPENSSL_malloc(ulModLen);
        temp = (Uint32 *) privexp;
        for (i = 0; i < ulModLen / 4; i++, temp++)
            *temp = CAV_SIG_HSM_KEY;

        memset(&(privexp[4]), 0, 8);
        memcpy(&(privexp[4]), (Uint8 *) & ulKey, 8);

        priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);

        if (priv_key == NULL)
            priv_key = BN_new();

        /* scalar */
        BN_bin2bn(privexp, ulModLen, priv_key);

        EC_KEY_set_private_key(eckey, priv_key);

        if (!PEM_write_ECPrivateKey(fd, eckey, NULL, NULL, 0, NULL, NULL))
            goto err;
    }
    printf
        ("\n\nPrivate Key Handle is written to %s in fake PEM format\n",
         KeyFile);
    ulRet = 0;

err:
    if (fd)
        fclose(fd);
    if (privexp)
        OPENSSL_free(privexp);
    if (rsa)
        RSA_free(rsa);
    if (pModulus)
        free(pModulus);
    if (eckey)
        EC_KEY_free(eckey);
    if (ctx)
        BN_CTX_free(ctx);
    if (pub_key)
        EC_POINT_free(pub_key);
    if (group)
        EC_GROUP_free(group);

    if (ulRet != 0)
        printf("\n\tError in writing private key file\n");
    else
        printf("\n\tgetCaviumPrivKey returned: 0x%02x %s%s\n",
               ulRet, ulRet?"\n\n\t":": ", Cfm2ResultAsString(ulRet));

    return ulRet;
}

/************************************************************************************
 *
 * FUNCTION     : IsValidKeyHandlefile
 *
 * DESCRIPTION  : checks input key file has a valid private key handle.
 *
 * PARAMETERS   : input:  PrivateKey file name
 *
 *                output:  Returns  non-zero on Error
 *                                  0 on Success
 *
 *******************************************************************************/

Uint32 IsValidKeyHandlefile(int argc, char **argv)
{

    Uint32 ulRet = -1;
    Uint32 i = 0;
    Uint8 bHelp = FALSE;
    RSA *rsa = NULL;

    Uint8 *privexp = NULL;
    Uint8 bFile = FALSE;
    FILE *fd = NULL;
    char *key_file = NULL;
    Uint32 ulKeyHandle = 0;

    Uint64 *pulKeyArray = 0;
    Uint32 ulKeyArrayLen = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        else if ((!bFile) && (strcmp(argv[i], "-f") == 0)
                 && (argc > i + 1)) {
            if (argv[i + 1] != NULL) {
                key_file = argv[i + 1];
                bFile = TRUE;
            }
        }

        else
            bHelp = TRUE;

    }

    // ensure that we have all the required args
    if (!bHelp && !bFile) {
        printf("\n\tError: Key File (-f) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nChecks given key file has key handle or real key \n(supported for RSA keys only)");
        printf("\n");
        printf("\nSyntax:  IsValidKeyHandlefile -h -f <key file>");
        printf("\n\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -f  specifies the RSA private key file name");
        printf("\n");
        goto exit;
    }

    rsa = RSA_new();

    if (!rsa->n && ((rsa->n = BN_new()) == NULL))
        goto ret;
    if (!rsa->d && ((rsa->d = BN_new()) == NULL))
        goto ret;
    if (!rsa->e && ((rsa->e = BN_new()) == NULL))
        goto ret;
    if (!rsa->p && ((rsa->p = BN_new()) == NULL))
        goto ret;
    if (!rsa->q && ((rsa->q = BN_new()) == NULL))
        goto ret;
    if (!rsa->dmp1 && ((rsa->dmp1 = BN_new()) == NULL))
        goto ret;
    if (!rsa->dmq1 && ((rsa->dmq1 = BN_new()) == NULL))
        goto ret;
    if (!rsa->iqmp && ((rsa->iqmp = BN_new()) == NULL))
        goto ret;

    fd = fopen(key_file, "r");
    if (!fd) {
        printf("\n\n \t error in opening file %s \n\n", key_file);
        ulRet = 0;
        goto ret;
    }

    if (!PEM_read_RSAPrivateKey(fd, &rsa, NULL, NULL))
        goto ret;

    privexp = OPENSSL_malloc(BN_num_bytes(rsa->d));
    BN_bn2bin(rsa->d, privexp);

    if ((*(Uint32 *) privexp == CAV_SIG_IMPORTED_KEY) ||
        (*(Uint32 *) privexp == CAV_SIG_HSM_KEY)) {
        ulKeyHandle = *(Uint32 *) & (privexp[8]);
        /* Determine Key Handle(s) Found and Place in Key Handle Array */

        ulRet = Cfm2FindKey(session_handle,
                            0, 3, -1, -1,
                            NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0,
                            NULL, &ulKeyArrayLen);
        if (ulKeyArrayLen) {
            /* Allocate Key Handle(s) Array */
            pulKeyArray = (Uint64 *) calloc(ulKeyArrayLen, sizeof(Uint64));
            if (pulKeyArray == 0) {
                ulRet = ERR_MEMORY_ALLOC_FAILURE;
                goto ret;
            } else {
                // Find All Keys of Key Type and Key Label
                ulRet =
                    Cfm2FindKey(session_handle,
                                0, 3, -1, -1,
                                NULL, 0, NULL, 0, NULL, 0, NULL,
                                0, NULL, 0, 0, pulKeyArray,
                                &ulKeyArrayLen);
                if (ulRet)
                    goto ret;
                // Print Key Handle Array
                //HexPrint((Uint8*)pKeyArray, ulKeyArrayLen*8);
                if (ulKeyArrayLen) {
                    for (i = 0; i <= ulKeyArrayLen - 1; i++) {
                        if ((Uint32) (pulKeyArray[i]) == ulKeyHandle) {
                            printf
                                ("\n\n \tInput file has key handle: %d \n\n",
                                 ulKeyHandle);
                            ulRet = 0;
                            goto ret;
                        }
                    }
                    ulRet = 0;
                    printf
                        ("\n\n \tInput file has invalid key handle: %d \n",
                         ulKeyHandle);
                    goto ret;
                } else {
                    printf
                        ("\n\n \tInput file has invalid key handle: %d \n",
                         ulKeyHandle);
                    ulRet = 0;
                    goto ret;
                }
            }
        } else {
            printf
                ("\n\n \tInput file has invalid key handle: %d \n",
                 ulKeyHandle);
            ulRet = 0;
            goto ret;
        }
    } else {
        printf("\n\n \tInput key file has real private key \n\n");
        ulRet = 0;
    }

  ret:

    if (ulRet == -1)
        printf("\n\n: \terror in Reading private key file %s \n\n",
               key_file);
    else if (ulRet)
        printf("\n\n \t IsValidKeyHandlefile return  0x%02x  %s\n\n",
               ulRet, Cfm2ResultAsString(ulRet));
  exit:
    if (fd)
        fclose(fd);
    if (privexp)
        OPENSSL_free(privexp);
    if (rsa)
        RSA_free(rsa);
    if (pulKeyArray)
        free(pulKeyArray);

    return ulRet;
}

Uint32 getCert(int argc, char **argv)
{
    Uint32 i = 0;
    Uint32 ulRet = 0;
    Uint8 bHelp = FALSE;
    Uint8 bCertFile = FALSE;
    Uint8 bCertSubject = FALSE;
#ifndef _WIN32
    Uint8 cert_buf[4096] = { };
#else
    Uint8 cert_buf[4096] = { 0 };
#endif
    Uint32 cert_len = 4096;
    char *cert_file = NULL;
    CertSubject cert_subject = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;
        else if ((!bCertFile) && (strcmp(argv[i], "-f") == 0) &&
                 (argc > i + 1)) {
            cert_file = argv[i + 1];
            bCertFile = TRUE;
        }
        // cert subject
        else if ((!bCertSubject) && (strcmp(argv[i], "-s") == 0)
                 && (argc > i + 1))
            bCertSubject = readIntegerArg(argv[i + 1], &cert_subject);
        else
            bHelp = TRUE;
    }

    if (!bHelp && !bCertFile) {
        printf("\n\tCertificate file (-f) is missing \n");
        bHelp = TRUE;
    }

    if (!bHelp && !bCertSubject) {
        printf("\n\tCertificate Subject (-s) is missing \n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf("\nGets Certificate from the HSM");
        printf("\n");
        printf("\nSyntax: getCert -f <cert-file> -s <cert-subject>");
        printf("\n");
        printf("\nWhere: -h     displays this information");
        printf("\n       -f     specifies the certificate file name");
        printf("\n       -s     specifies owner of the certificate");
        printf("\n              (ex: CAVIUM - 1,\n\t\t   HSM - 2,\n\t\t   PARTITION_OWNER - 4,"
               "\n\t\t   PARTITION - 8,\n\t\t   PARTITION_CERT_ISSUED_BY_HSM - 16,"
               "\n\t\t   HSM_OWNER_CERT - 32,\n\t\t   HSM_CERT_ISSUED_BY_HO - 64)");
        printf("\n\n");
        return ulRet;
    }

    ulRet = Cfm3GetCert(session_handle, cert_subject, cert_buf, &cert_len);

    if (RET_OK == ulRet) {
        printf("\n\tCfm3GetCert() returned %d :%s\n", ulRet,
               Cfm2ResultAsString(ulRet));
        /* write the pem formatted cert file */
        ulRet = write_file(cert_file, cert_buf, cert_len);
        if (ulRet != 0) {
            printf("\n\tError: Empty file: %s\n", cert_file);
            return -1;
        }
    } else {
        printf("\n\tCfm3GetCert() failed with erro code %d :%s\n",
               ulRet, Cfm2ResultAsString(ulRet));
        return 0;
    }

    return ulRet;
}

#ifdef LIQUID_SECURITY_CLIENT
#ifdef ENABLE_CFMUTIL_DAEMON_CONFG
Uint32 addServerNode(int argc, char **argv)
{
    Uint8 bHelp = FALSE;
    Uint8 i = 0;
    Uint32 ulRet = 0;

    Uint8 bIpAddr = FALSE;
    char *pIpAddr = NULL;
    Uint32 uIpAddrLen = 0;

    Uint8 bPort = FALSE;
    Uint32 uPort = 0;

    Uint8 bNodeId = FALSE;
    Uint32 uNodeId = 0;

    Uint8 bZoneId = FALSE;
    Uint32 uZoneId = 0;

    Uint8 bFlag = FALSE;
    char *pFlag = NULL;
    Uint32 uFlag = 0;
    Uint32 uFlagLen = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // IP Address
        else if ((!bIpAddr) && (strcmp(argv[i], "-i") == 0)
                 && (argc > i + 1)) {
            struct sockaddr_in sa;
            bIpAddr = readArgAsString(argv[i + 1], &pIpAddr, &uIpAddrLen);
            /*Add check for proper IP Address */
            if (inet_pton(AF_INET, pIpAddr, &(sa.sin_addr)) != 1) {
                printf("\n\t Error: Invalid ip address : %s.\n", pIpAddr);
                bHelp = TRUE;
            }
        }
        // port number
        else if ((!bPort) && (strcmp(argv[i], "-p") == 0)
                 && (argc > i + 1)) {
            bPort = readIntegerArg(argv[i + 1], &uPort);
            if (uPort < 0 || uPort > MAX_PORT_NUM) {
                printf
                    ("\n\t Error: port:%d. Supported port number values are 0 to %d.\n",
                     uPort, MAX_PORT_NUM);
                bHelp = TRUE;
            }
        }
        // node ID
        else if ((!bNodeId) && (strcmp(argv[i], "-n") == 0)
                 && (argc > i + 1)) {
            bNodeId = readIntegerArg(argv[i + 1], &uNodeId);
            if (uNodeId < 0 || uNodeId > MAX_NODEID_NUM) {
                printf
                    ("\n\t Error: NodeId:%d. Supported nodeId values are 0 to %d.\n",
                     uNodeId, MAX_NODEID_NUM);
                bHelp = TRUE;
            }
        }
        // zone ID
        else if ((!bZoneId) && (strcmp(argv[i], "-z") == 0)
                 && (argc > i + 1)) {
            bZoneId = readIntegerArg(argv[i + 1], &uZoneId);
            if (uZoneId < 0 || uZoneId > MAX_ZONEID_NUM) {
                printf
                    ("\n\t Error: zoneID:%d. Supported zoneId values are 0 to %d.\n",
                     uZoneId, MAX_ZONEID_NUM);
                bHelp = TRUE;
            }
        }

        else if ((!bFlag) && (strcmp(argv[i], "-e") == 0)
                 && (argc > i + 1)) {
            bFlag = readArgAsString(argv[i + 1], &pFlag, &uFlagLen);
            if (strncasecmp("Y", pFlag, uFlagLen) == 0
                || strncasecmp("YES", pFlag, uFlagLen) == 0) {
                uFlag = 1;      //SERVER_ENABLE
            } else if (strncasecmp("N", pFlag, uFlagLen) == 0
                       || strncasecmp("NO", pFlag, uFlagLen) == 0) {
                uFlag = 2;      //SERVER_DISABALE
            } else {
                printf
                    ("\n\t Error: -e %s. Supported flag value is <Y/N>\n",
                     pFlag);
                bHelp = TRUE;
            }
        } else
            bHelp = TRUE;
    }

    if (!bHelp && !bIpAddr) {
        printf("\n\t Error: Ip Address (-i) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bPort) {
        printf("\n\t Error: Port number (-p) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bNodeId) {
        printf("\n\t Error: Node id is (-n) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bZoneId) {
        printf("\n\t Error: Zone id is (-z) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bFlag) {
        printf("\n\t Error: enabled flag is (-e (Y/N)) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nAdd server node to the cluster providing server ip address, port number, nodeid, zoneid and enable flag.");
        printf("\n");
        printf
            ("\nSyntax: addServerNode -h -i <ip address> -p <port number> -n <nodeid> -z <zoneid> -e <Y/N>");
        printf("\n\n");
        printf("\nWhere: -h  displays this information");
        printf("\n       -i  specifies the server node ip address");
        printf("\n       -p  specifies the server node port number");
        printf("\n       -n  specifies the server node node id");
        printf("\n       -z  specifies the server node zone id");
        printf
            ("\n       -e <Y/N> specifies whether server node to be enable or disable");
        printf("\n");
        ulRet = RET_INVALID_INPUT;
        goto exit_error;
    }

    print_debug("%s(): IP:%s Port:%d Node:%d Zone:%d Flag:%d\n",
                __FUNCTION__, pIpAddr, uPort, uNodeId, uZoneId, uFlag);

    ulRet =
        Cfm3AddServerNode(pIpAddr, uIpAddrLen, uPort, uNodeId, uZoneId,
                          uFlag);
    if (!ulRet) {
        printf("\n\t%s: Success.\n", __FUNCTION__);
    } else {
        printf("\n\t%s: Fail.\n", __FUNCTION__);
    }

  exit_error:
    if (pIpAddr)
        free(pIpAddr);
    if (pFlag)
        free(pFlag);

    return ulRet;
}

Uint32 removeServerNode(int argc, char **argv)
{
    Uint8 bHelp = FALSE;
    Uint8 i = 0;
    Uint32 ulRet = 0;

    Uint8 bNodeId = FALSE;
    Uint32 uNodeId = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // node ID
        else if ((!bNodeId) && (strcmp(argv[i], "-n") == 0)
                 && (argc > i + 1)) {
            bNodeId = readIntegerArg(argv[i + 1], &uNodeId);
            if (uNodeId < 0 || uNodeId > MAX_NODEID_NUM) {
                printf
                    ("\n\t Error: NodeId:%d. Supported nodeId values are 0 to %d.\n",
                     uNodeId, MAX_NODEID_NUM);
                bHelp = TRUE;
            }
        } else
            bHelp = TRUE;
    }

    if (!bHelp && !bNodeId) {
        printf("\n\t Error: Node id (-n) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nRemove server node with provided nodeid from the cluster.");
        printf("\n");
        printf("\nSyntax: removeServerNode -h -n <nodeid> ");
        printf("\n\n");
        printf("\nWhere: -h  displays this information");
        printf
            ("\n       -n  remove the server node with nodeid from the cluster.");
        printf("\n");
        return RET_INVALID_INPUT;
    }
    print_debug("Node:%d\n", uNodeId);

    ulRet = Cfm3RemoveServerNode(uNodeId);
    if (!ulRet) {
        printf("\n\t%s: Success.\n", __FUNCTION__);
    } else {
        printf("\n\t%s: Fail.\n", __FUNCTION__);
    }
    return ulRet;
}

Uint32 modifyServerNode(int argc, char **argv)
{
    Uint8 bHelp = FALSE;
    Uint8 i = 0;
    Uint32 ulRet = 0;

    Uint8 bIpAddr = FALSE;
    char *pIpAddr = NULL;
    Uint32 uIpAddrLen = 0;

    Uint8 bPort = FALSE;
    Uint32 uPort = 0;

    Uint8 bNodeId = FALSE;
    Uint32 uNodeId = 0;

    Uint8 bFlag = FALSE;
    char *pFlag = NULL;
    Uint32 uFlag = 0;
    Uint32 uFlagLen = 0;

    for (i = 2; i < argc; i = i + 2) {
        // help
        if (strcmp(argv[i], "-h") == 0)
            bHelp = TRUE;

        // IP Address
        else if ((!bIpAddr) && (strcmp(argv[i], "-i") == 0)
                 && (argc > i + 1)) {
            struct sockaddr_in sa;
            bIpAddr = readArgAsString(argv[i + 1], &pIpAddr, &uIpAddrLen);
            /*Add check for proper IP Address */
            if (inet_pton(AF_INET, pIpAddr, &(sa.sin_addr)) != 1) {
                printf("\n\t Error: Invalid ip address : %s.\n", pIpAddr);
                bHelp = TRUE;
            }
        }
        // port number
        else if ((!bPort) && (strcmp(argv[i], "-p") == 0)
                 && (argc > i + 1)) {
            bPort = readIntegerArg(argv[i + 1], &uPort);
            if (uPort < 0 || uPort > MAX_PORT_NUM) {
                printf
                    ("\n\t Error: port:%d. Supported port number values are 0 to %d.\n",
                     uPort, MAX_PORT_NUM);
                bHelp = TRUE;
            }
        }
        // node ID
        else if ((!bNodeId) && (strcmp(argv[i], "-n") == 0)
                 && (argc > i + 1)) {
            bNodeId = readIntegerArg(argv[i + 1], &uNodeId);
            if (uNodeId < 0 || uNodeId > MAX_NODEID_NUM) {
                printf
                    ("\n\t Error: NodeId:%d. Supported nodeId values are 0 to %d.\n",
                     uNodeId, MAX_NODEID_NUM);
                bHelp = TRUE;
            }
        }

        else if ((!bFlag) && (strcmp(argv[i], "-e") == 0)
                 && (argc > i + 1)) {
            bFlag = readArgAsString(argv[i + 1], &pFlag, &uFlagLen);
            if (strncasecmp("Y", pFlag, uFlagLen) == 0
                || strncasecmp("YES", pFlag, uFlagLen) == 0) {
                uFlag = 1;      //SERVER_ENABLE
            } else if (strncasecmp("N", pFlag, uFlagLen) == 0
                       || strncasecmp("NO", pFlag, uFlagLen) == 0) {
                uFlag = 2;      //SERVER_DISABALE
            } else {
                printf
                    ("\n\t Error: -e %s. Supported flag value is <Y/N>\n",
                     pFlag);
                bHelp = TRUE;
            }
        } else
            bHelp = TRUE;
    }

    if (!bHelp && !bIpAddr) {
        printf("\n\t Error: Ip Address (-i) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bPort) {
        printf("\n\t Error: Port number (-p) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bNodeId) {
        printf("\n\t Error: Node id is (-n) is missing.\n");
        bHelp = TRUE;
    }

    if (!bHelp && !bFlag) {
        printf("\n\t Error: enabled flag is (-e (Y/N)) is missing.\n");
        bHelp = TRUE;
    }

    if (bHelp) {
        printf("\n");
        printf("\nDescription");
        printf("\n===========");
        printf
            ("\nModify server node with nodeid's ip address, port number and enable flag.");
        printf("\n");
        printf
            ("\nSyntax: modifyServerNode -h -n <nodeid> -i <ip address> -p <port number> -e <Y/N>");
        printf("\n\n");
        printf("\nWhere: -h  displays this information");
        printf
            ("\n       -n  specifies the server node node id which is suppossed to be modified");
        printf("\n       -i  specifies the server node new ip address");
        printf("\n       -p  specifies the server node port number");
        printf
            ("\n       -e <Y/N> specifies whether server node to be enable or disable");
        printf("\n");
        ulRet = RET_INVALID_INPUT;
        goto exit_error;
    }

    print_debug("IP:%s Port:%d Node:%d Flag:%d\n", pIpAddr, uPort, uNodeId,
                uFlag);

    ulRet =
        Cfm3ModifyServerNode(pIpAddr, uIpAddrLen, uPort, uNodeId, uFlag);
    if (!ulRet) {
        printf("\n\t%s: Success.\n", __FUNCTION__);
    } else {
        printf("\n\t%s: Fail.\n", __FUNCTION__);
    }

  exit_error:
    if (pIpAddr)
        free(pIpAddr);
    if (pFlag)
        free(pFlag);

    return ulRet;
}

#endif                          /* ENABLE_CFMUTIL_DAEMON_CONFG */
#endif                          /*LIQUID_SECURITY_CLIENT */

/****************************************************************************\
 *
 * FUNCTION     : CfmUtil_main
 *
 * DESCRIPTION  : The "main" function of the Cfm2Util Utility to allow command
 *                line arguments to be used to make Cavium Shim API calls.
 *                This function is called each time a command is entered.
 *
 * PARAMETERS   : argc, **argv
 *
 * RETURN VALUE : int
 *
 \****************************************************************************/
int CfmUtil_main(int argc, char **argv)
{

    char *pszArg = "help";

    if (argc > 1)
        pszArg = argv[1];

    if (strcmp(pszArg, "getHSMInfo") == 0)
        getHSMInfo(argc, argv);
    else if (strcmp(pszArg, "getPartitionInfo") == 0)
        getPartitionInfo(argc, argv);
    else if (strcmp(pszArg, "loginStatus") == 0)
        loginStatus(argc, argv);
    else if (strcmp(pszArg, "listUsers") == 0)
        listUsers(argc, argv);
    else if (strcmp(pszArg, "loginHSM") == 0)
        login(argc, argv);
    else if (strcmp(pszArg, "logoutHSM") == 0)
        logout(argc, argv);
    else if (strcmp(pszArg, "getToken") == 0)
        getToken(argc, argv);
    else if (strcmp(pszArg, "delToken") == 0)
        delToken(argc, argv);
    else if (strcmp(pszArg, "approveToken") == 0)
        approveToken(argc, argv);
    else if (strcmp(pszArg, "listTokens") == 0)
        listTokens(argc, argv);
#if 0
#ifndef _WIN32
    else if (strcmp(pszArg, "registerMofnPubKey") == 0)
        registerMofnPubKey(argc, argv);
#endif
#endif
    else if ((strcmp(pszArg, "rsaGenKeyPair") == 0) ||
             (strcmp(pszArg, "genRSAKeyPair") == 0))
        genRSAKeyPair(argc, argv);
    else if ((strcmp(pszArg, "dsaGenKeyPair") == 0) ||
             (strcmp(pszArg, "genDSAKeyPair") == 0))
        genDSAKeyPair(argc, argv);
    else if (strcmp(pszArg, "genECCKeyPair") == 0)
        genECCKeyPair(argc, argv);
    else if (strcmp(pszArg, "createPublicKey") == 0)
        createPublicKey(argc, argv);
    else if (strcmp(pszArg, "importPubKey") == 0)
        importPublicKey(argc, argv);
    else if (strcmp(pszArg, "exportPubKey") == 0)
        exportPublicKey(argc, argv);
    else if (strcmp(pszArg, "importPrivateKey") == 0)
        importPrivateKey(argc, argv);
    else if (strcmp(pszArg, "exportPrivateKey") == 0)
        exportPrivateKey(argc, argv);
    else if (strcmp(pszArg, "genPBEKey") == 0)
        genPBEKey(argc, argv);
    else if (strcmp(pszArg, "genSymKey") == 0)
        genSymKey(argc, argv);
    else if (strcmp(pszArg, "imSymKey") == 0)
        imSymKey(argc, argv);
    else if (strcmp(pszArg, "wrapKey") == 0)
        wrapKey(argc, argv);
    else if (strcmp(pszArg, "unWrapKey") == 0)
        unWrapKey(argc, argv);
    else if (strcmp(pszArg, "unWrapKeyWithSize") == 0)
        unWrapKeyWithSize(argc, argv);
    else if (strcmp(pszArg, "exSymKey") == 0)
        exSymKey(argc, argv);
    else if (strcmp(pszArg, "deleteKey") == 0)
        deleteKey(argc, argv);
#if 0
    else if (strcmp(pszArg, "shareKey") == 0)
        shareKey(argc, argv);
#endif
    else if (strcmp(pszArg, "setAttribute") == 0)
        setAttribute(argc, argv);
    else if (strcmp(pszArg, "getKeyInfo") == 0)
        getKeyInfo(argc, argv);
    else if (strcmp(pszArg, "findKey") == 0)
        findKey(argc, argv);
    else if (strcmp(pszArg, "findSingleKey") == 0)
        findSingleKey(argc, argv);
    else if (strcmp(pszArg, "getAttribute") == 0)
        getAttribute(argc, argv);
    else if (strcmp(pszArg, "listAttributes") == 0)
        listAttributes(argc, argv);
    else if (strcmp(pszArg, "insertMaskedObject") == 0)
        insertMaskedObject(argc, argv);
    else if (strcmp(pszArg, "extractMaskedObject") == 0)
        extractMaskedObject(argc, argv);
    else if (strcmp(pszArg, "listECCCurveIds") == 0)
        listECCCurveIds(argc, argv);
    else if (strcmp(pszArg, "aesWrapUnwrap") == 0)
        aesWrapUnwrap(argc, argv);
    else if (strcmp(pszArg, "aesUnwrapPkcs8Buffer") == 0)
        aesUnwrapPkcs8Buffer(argc, argv);
    else if (strcmp(pszArg, "sign") == 0)
        sign(argc, argv);
    else if (strcmp(pszArg, "verify") == 0)
        verify(argc, argv);
    else if (strcmp(pszArg, "getCert") == 0)
        getCert(argc, argv);
    else if (strcmp(pszArg, "Error2String") == 0)
        Error2String(argc, argv);
    else if ((strcmp(pszArg, "getPrivKeyfile") == 0) ||
             (strcmp(pszArg, "getCaviumPrivKey") == 0))
        getCaviumPrivKey(argc, argv);
    else if (strcmp(pszArg, "IsValidKeyHandlefile") == 0)
        IsValidKeyHandlefile(argc, argv);
#ifdef ENABLE_CFMUTIL_DAEMON_CONFG
    else if (strcmp(pszArg, "addServerNode") == 0)
        addServerNode(argc, argv);
    else if (strcmp(pszArg, "removeServerNode") == 0)
        removeServerNode(argc, argv);
    else if (strcmp(pszArg, "modifyServerNode") == 0)
        modifyServerNode(argc, argv);
#endif                          /* ENABLE_CFMUTIL_DAEMON_CONFG */
    else if (strcmp(pszArg, "exit") == 0)
        return ERR_EXIT_CFM1UTIL;       // force an exit
    else {
        // "help" or an unknown command
        Help_AllCommands(vector[0]);
    }

    return 0;
}

/****************************************************************************\
 *
 * FUNCTION     : HexPrint
 *
 * DESCRIPTION  : Displays Data of a Given Length in Hexidecimal Format
 *
 * PARAMETERS   : data, len
 *
 * RETURN VALUE : none
 *
 \****************************************************************************/
void HexPrint(Uint8 * data, Uint32 len)
{
    Uint32 i;
    //                  No Data or No Length Specified
    if (!data || !len)
        return;
    //                           Display Data
    for (i = 1; i <= len; i++) {
        //printf( "%02X ", data[i] );
        printf("%02X ", data[i - 1]);
        if ((i % 16) == 0)
            printf("\n");
    }
    if ((i % 16) != 0)
        printf("\n");

    printf("\n\n");
}

/****************************************************************************\
 *
 * FUNCTION     : Help_AllCommands
 *
 * DESCRIPTION  : Displays Help for All Commands Available
 *
 * PARAMETERS   : pAppName
 *
 * RETURN VALUE : none
 *
 \****************************************************************************/
void Help_AllCommands(char *pAppName)
{
    printf("\n");
    printf("\nHelp Commands Available:");
    printf("\n");
    printf
        ("\nSyntax: <command> -h                                     \n");
    printf("\n");
    printf("\n   Command               Description");
    printf("\n   =======               ===========");
    printf("\n");
    printf("\n   exit                   Exits this application");
    printf("\n   help                   Displays this information");

    printf("\n\n\tConfiguration and Admin Commands");
    printf("\n   getHSMInfo             Gets the HSM Information");
    printf("\n   getPartitionInfo       Gets the Partition Information");

    printf
        ("\n   listUsers              Lists all users of a partition   ");

    printf("\n   loginStatus            Gets the Login Information");
    printf("\n   loginHSM               Login to the HSM");
    printf("\n   logoutHSM              Logout from the HSM");

    printf("\n\n\tM of N commands");
    printf
        ("\n   getToken               Initiate an MxN service and get Token");
    printf("\n   delToken               delete Token(s)");
    printf("\n   approveToken           Approves an MxN service");
    printf
        ("\n   listTokens             List all Tokens in the current partition");

    printf("\n\n\tKey Generation Commands");
    printf("\n\n\tAsymmetric Keys:");
    printf("\n   genRSAKeyPair          Generates an RSA Key Pair");
    printf("\n   genDSAKeyPair          Generates a DSA Key Pair");
    printf("\n   genECCKeyPair          Generates an ECC Key Pair");
    printf("\n\n\tSymmetric Keys:");
    printf("\n   genPBEKey              Generates a PBE DES3 key");
    printf("\n   genSymKey              Generates a Symmetric keys");

    printf("\n\n\tKey Import/Export Commands");
    printf("\n   createPublicKey        Creates an RSA public key");
    printf("\n   importPubKey           Imports RSA/DSA/EC Public key");
    printf("\n   exportPubKey           Exports RSA/DSA/EC Public key");
    printf("\n   importPrivateKey       Imports RSA/DSA/EC private key");
    printf("\n   exportPrivateKey       Exports RSA/DSA/EC private key");
    printf("\n   imSymKey               Imports a Symmetric key");
    printf("\n   exSymKey               Exports a Symmetric key");
    printf("\n   wrapKey                Wraps a key from HSM using the specified handle");
    printf("\n   unWrapKey              UnWraps a key into HSM using the specified handle");
    printf("\n   unWrapKeyWithSize      UnWraps a key into HSM using the key size");

    printf("\n\n\tKey Management Commands");
    printf("\n   deleteKey              Delete Key");
#if 0
    printf
        ("\n   shareKey               Share Key with other users/sessions");
#endif
    printf("\n   setAttribute           Sets an attribute of an object");
    printf
        ("\n   getKeyInfo             Get Key Info about shared users/sessions");

    printf("\n   findKey                Find Key");
    printf("\n   findSingleKey          Find single Key");
    printf
        ("\n   getAttribute           Reads an attribute from an object");

    printf("\n\n\tCertificate Setup Commands");
    printf
        ("\n   getCert                Gets Partition Certificates stored on HSM");

    printf("\n\n\tKey Transfer Commands");
    printf("\n   insertMaskedObject     Inserts a masked object");
    printf("\n   extractMaskedObject    Extracts a masked object");

    printf("\n\n\tManagement Crypto Commands");
    printf("\n   sign                   Generates a signature");
    printf("\n   verify                 Verifies a signature");
    printf("\n   aesWrapUnwrap          Does NIST AES Wrap/Unwrap");
    printf("\n   aesUnwrapPkcs8Buffer   Does KW PKCS5 Pad Unwrap");

#ifdef ENABLE_CFMUTIL_DAEMON_CONFG
    printf("\n\n\tServer Management Commands");
    printf
        ("\n   addServerNode              Add server node in cluster configuration");
    printf
        ("\n   removeServerNode           Remove server node from cluster configuration");
    printf
        ("\n   modifyServerNode           Modify server node in cluster configuration");
#endif                          /* ENABLE_CFMUTIL_DAEMON_CONFG */

    printf("\n\n\tHelper Commands");
    printf("\n   Error2String           Converts Error codes to Strings");
    printf
        ("\n                          save key handle in fake PEM format");
    printf("\n   getCaviumPrivKey       Saves an RSA private key handle");
    printf("\n                          in fake PEM format");
    printf("\n   IsValidKeyHandlefile   Checks if private key file has");
    printf("\n                          an HSM key handle or a real key");
    printf
        ("\n   listAttributes         List all attributes for getAttributes");
    printf("\n   listECCCurveIds        List HSM supported ECC CurveIds");
    printf("\n\n");
}

/****************************************************************************\
 *
 * FUNCTION     : ReadBinaryFile
 *
 * DESCRIPTION  : Reads a binary file with the input file, allocates memory
 *                to read it and returns the content using the input pointers.
 *                Returns 1 if successful.
 *
 * PARAMETERS   : char *pbFileName
 *                char **ppMemBlock
 *                unsigned long *pulMemSize
 *
 * RETURN VALUE : int
 *
 * CAUTION!! Memory allocated for *ppMemBlock should be free by user
 \****************************************************************************/
int ReadBinaryFile(char *pbFileName, char **ppMemBlock,
                   unsigned int *pulMemSize)
{
    int isOK = 1;               // Return Code
    int fileHandle;             // File Handle
    int isFileOpen = 0;         // File Open Flag

    //      Verify Pointers
    if (!pbFileName || !ppMemBlock || !pulMemSize) {
        isOK = 0;
    }
    //      Open File
    if (isOK) {
#ifndef _WIN32
        fileHandle = open(pbFileName, O_RDONLY);
#else
        fileHandle = open(pbFileName, O_RDONLY | O_BINARY);
#endif
        if (fileHandle == -1) {
            isOK = 0;
        } else {
            isFileOpen = 1;
        }
    }
    //      Get File Size
    if (isOK) {
        struct stat fileStat;
        if (fstat(fileHandle, &fileStat)) {
            isOK = 0;
        } else if (0 == fileStat.st_size) {
            printf("\n\t %s is an empty file.\n", pbFileName);
            isOK = 0;
        }
        *pulMemSize = fileStat.st_size;
    }
    if (isOK) {
        // Allocate Memory to Read File
        *ppMemBlock = CALLOC_WITH_CHECK(1, *pulMemSize);
    }
    //   Read File
    if (isOK) {
        unsigned int bytesSupplied = (unsigned int) *pulMemSize;
        unsigned int bytesRead;

        bytesRead = read(fileHandle, *ppMemBlock, bytesSupplied);
        if (bytesRead <= 0) {
            //  Error While Reading
            isOK = 0;
        }
    }
    //    Close File Handle
    if (isFileOpen) {
#ifdef _WIN32
        _close(fileHandle);
#else
        close(fileHandle);
#endif
    }
    //    Free Allocated Memory
    return isOK;
}

#ifndef _WIN32
int map_file(char *inPathName, void **outDataPtr, size_t * outDataLength)
{
    int outError = 0;
    int fileDescriptor;
    struct stat statInfo;
    // Return safe values on error.
    *outDataPtr = NULL;
    *outDataLength = 0;

    // Open the file.
    fileDescriptor = open(inPathName, O_RDONLY, 0);

    if (fileDescriptor < 0) {
        outError = errno;
        print_debug("map_file: open failed\n");
    } else {
        // We now know the file exists. Retrieve the file size.
        if (fstat(fileDescriptor, &statInfo) != 0) {
            outError = errno;
            print_debug("map_file: fstat failed\n");
        } else {
            usleep(1000);
            // Map the file into a read-only memory region.
            *outDataPtr =
                mmap(0, statInfo.st_size, PROT_READ, MAP_SHARED,
                     fileDescriptor, 0);
            if (*outDataPtr == MAP_FAILED) {
                outError = errno;
                print_debug("map_file: mmap failed\n");
            } else {
                *outDataLength = statInfo.st_size;
            }
        }
        close(fileDescriptor);
    }
    return outError;
}

int ReadFileByMap(char *pbFileName, char **ppMemBlock,
                  unsigned int *pulMemSize)
{
    int isOK = 1;               // Return Code
    size_t len1;
    void *data1;

    //    Verify Pointers
    if (!pbFileName || !ppMemBlock || !pulMemSize) {
        isOK = 0;
        return isOK;
    }
    //    Open File
    if (map_file(pbFileName, &data1, &len1)) {
        print_debug("Could not map file %s\n", pbFileName);
        isOK = 0;
        return isOK;
    }

    *pulMemSize = len1;
    *ppMemBlock = CALLOC_WITH_CHECK(1, *pulMemSize);
    if (!*ppMemBlock) {
        isOK = 0;
    } else {
        memcpy(*ppMemBlock, data1, len1);
    }
    munmap(data1, len1);

    return isOK;

}
#endif
//******************************************************************8
//
//                        write bin file
//
//*********************************************************************
int WriteBinaryFile(char *pbFileName, char *pMemBlock,
                    unsigned long ulMemSize)
{
    int isOK = 1;               // Return Code
    int fileHandle;             // File Handle
    int isFileOpen = 0;         // File Open Flag

    //       Verify Pointers
    if (!pbFileName || !pMemBlock || (ulMemSize <= 0)) {
        isOK = 0;
    }
    //       Open File
    if (isOK) {
#ifndef _WIN32
        fileHandle =
            open(pbFileName, O_WRONLY | O_CREAT | O_TRUNC,
                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#else
        fileHandle =
            open(pbFileName, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
#endif
        if (fileHandle == -1) {
            isOK = 0;
        } else {
            isFileOpen = 1;
        }
    }
    // Write file
    if (isOK) {
        unsigned int bytesRead;
        bytesRead = write(fileHandle, pMemBlock, ulMemSize);
        if (bytesRead <= 0) {
            isOK = 0;
        }
    }
    //    Close File Handle
    if (isFileOpen) {
#ifdef _WIN32
        _close(fileHandle);
#else
        close(fileHandle);
#endif
    }
    return isOK;
}

// reads a line of input and NULL terminates it, returning len without NULL
unsigned int GetConsoleString(char *pPrompt,
                              char *pBuffer, unsigned int nBufferSize)
{
    unsigned int nCharsRead = 0;
    int ch;
    if (pPrompt) {
        printf("%s ", pPrompt);
    }
    ch = getchar();
    while ((ch != EOF) && (ch != '\n')) {
        if ((ch != '\r') && ((nCharsRead + 1) < nBufferSize)) {
            pBuffer[nCharsRead++] = ch;
        }
        ch = getchar();
    }
    // Null terminate the string before returning
    pBuffer[nCharsRead] = 0;
    return (nCharsRead);
}

/* CAUTION!! Memory allocated should be freed*/
int getAttributeValue(Uint32 ulAttribute,
                      Uint8 ** pAttribute, Uint32 * ulAttributeLen)
{
    Uint32 ulRet = 0;

    switch (ulAttribute) {

        // Boolean Attributes
#if 0
    case OBJ_ATTR_ENCRYPT:
    case OBJ_ATTR_DECRYPT:
    case OBJ_ATTR_WRAP:
    case OBJ_ATTR_UNWRAP:
    case OBJ_ATTR_TRUSTED:
    case OBJ_ATTR_WRAP_WITH_TRUSTED:
    case OBJ_ATTR_DESTROYABLE:
#endif
    case OBJ_ATTR_TOKEN:
        {
            Uint32 ulVal = 0;
            Uint8 bValue = 0;
            printf("\t\tThis attribute is defined as a boolean value.\n");
            printf("\t\tEnter the boolean attribute value (0 or 1):");
            if (1 != scanf("%d", &ulVal)) {
                printf("\nError reading the user input value\n");
                ulRet = ERR_INVALID_USER_INPUT;
                break;
            }

            if (ulVal)
                bValue = '1';
            else if (ulVal == 0)
                bValue = '0';
            //bValue = (Uint8)ulVal;
            *pAttribute = (Uint8 *) CALLOC_WITH_CHECK(1, 2);

            print_debug("\t\tSending the attribute value %d:\n", bValue);
            if (*pAttribute == NULL) {
                ulRet = ERR_MEMORY_ALLOC_FAILURE;
            } else {
                memcpy(*pAttribute, &bValue, sizeof(bValue));
                (*pAttribute)[1] = '\0';
                *ulAttributeLen = sizeof(bValue) + 1;
            }
            print_debug("\t\tSending the attribute of size %d:\n",
                        *ulAttributeLen);
        }
        break;

#if 0
        // string attributes
    case OBJ_ATTR_LABEL:
        {
            Uint8 Buffer[1000];
            Uint8 *pBuffer = Buffer;
            printf("\t\tThis attribute is defined as a string.\n");
            printf
                ("\t\tEnter the string attribute value (no spaces, max 128 characters):");
            scanf("%s", pBuffer);
            if (strlen((char *) pBuffer) > 128)
                return ERR_DATA_LEN_RANGE;
            *pAttribute =
                (Uint8 *) CALLOC_WITH_CHECK(1, strlen((char *) pBuffer));
            if (pAttribute == 0) {
                ulRet = ERR_MEMORY_ALLOC_FAILURE;
            } else {
                memcpy(*pAttribute, pBuffer, strlen((char *) pBuffer));
                *ulAttributeLen = strlen((char *) pBuffer);
            }
        }
        break;
#endif

    default:
        printf("\n\tThis attribute is either not modifiable or unknown");
        ulRet = ERR_ARGUMENTS_BAD;
        break;
    }

    return ulRet;
}

/*
 * getPswdString()
 * ==============
 * This function retrieves a pin string from the user.
 * It modifies the console mode before starting so that the
 * characters the user types are not echoed, and a '*'
 * character is displayed for each typed character instead.
 *
 * Backspace is supported, but we don't get any fancier than that.
 *
 * If -1 is passed in for ulMinLen, the size constraints are not checked.
 *
 * return codes
 *       0 == OK
 *       1 == problem with len constraints
 *       2 == problem with input params
 *       3+ == problems manipulating the console
 */

Uint32 getPswdString(char *pw, int *pulLen, int ulMinLen, int ulMaxLen)
{
    char *pBuffer = pw;
    int len = 0;
    char c = 0;
    int retVal = 0;

    // Unfortunately, the method of turning off character echo is different for
    // Windows and Unix platforms.  So we have to conditionally compile the appropriate
    // section.  Even the basic password retrieval is slightly different, since
    // Windows and Unix use different character codes for the return key.

#ifdef _WIN32
    DWORD mode;

    if ((pw == 0) || (ulMinLen == 0) || (ulMaxLen < ulMinLen))
        return 2;

    *pulLen = 0;
    *pw = '\0';

    /* This console mode stuff only applies to windows.
       We'll have to do something else when it comes to unix */
    if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode)) {
        if (SetConsoleMode
            (GetStdHandle(STD_INPUT_HANDLE),
             mode & (!ENABLE_ECHO_INPUT))) {
            while ((c != '\r') && (retVal == 0)) {
                // wait for a character to be hit
                while (!_kbhit()) {
                    Sleep(100);
                }
                // get it
                c = _getch();

                // check for carriage return
                if (c != '\r') {
                    // check for backspace
                    if (c != '\b') {
                        // neither CR nor BS -- add it to the password string
                        if (len >= ulMaxLen) {
                            printf("\b \b");
                            printf("*");
                            *pw = c;
                        } else {
                            printf("*");
                            *pw++ = c;
                            len++;
                        }
                    } else {
                        // handle backspace -- delete the last character & erase it from the screen
                        if (len > 0) {
                            pw--;
                            len--;
                            printf("\b \b");
                        }
                    }
                }
            }
            // Add the zero-termination
            *pw = '\0';

            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
            printf("\n");
        }
    }
#else                           // all other unix like systems

    struct termios tio;
    int fd;
    int rc;
    cc_t old_min, old_time;
    char termbuff[200];

    if ((pw == 0) || (ulMinLen == 0) || (ulMaxLen < ulMinLen))
        return 2;

    *pulLen = 0;
    *pw = '\0';

    // Before we change mode on the terminal, we need to flush stdout (else
    // our prompt doesn't get shown until the user starts typing).
    fflush(stdout);

    fd = open(ctermid(termbuff), O_RDONLY);
    if (fd == -1) {
        return 3;
    }

    rc = tcgetattr(fd, &tio);
    if (rc == -1) {
        close(fd);
        return 3;
    }

    /* turn off canonical mode & echo */
    old_min = tio.c_cc[VMIN];
    old_time = tio.c_cc[VTIME];
    tio.c_lflag = tio.c_lflag & ~ICANON & ~ECHO;
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;

    rc = tcsetattr(fd, TCSADRAIN, &tio);
    if (rc == -1) {
        close(fd);
        return 3;
    }

    while ((c != '\n') && (retVal == 0)) {
        rc = read(fd, &c, 1);
        if (rc != 0) {
            if (c != '\n') {
                // check for backspace
                if (c != '\b' && c != 127) {    // BS can be either 0x8(\b) or 0x127 on unix
                    // neither CR nor BS -- add it to the password string
                    if (len >= ulMaxLen) {
                        printf("\b \b");
                        printf("*");
                        fflush(stdout);
                        *pw = c;
                    } else {
                        printf("*");
                        fflush(stdout);
                        *pw++ = c;
                        len++;
                    }
                } else {
                    // handle backspace -- delete the last character & erase it from the screen
                    if (len > 0) {
                        pw--;
                        len--;
                        printf("\b \b");
                        fflush(stdout);
                    }
                }
            }
        } else {
            close(fd);
            return 3;
        }
    }
    *pw++ = '\0';
    printf("\n");

    /* return terminal to its original state */
    tio.c_lflag = tio.c_lflag | ICANON | ECHO;
    tio.c_cc[VMIN] = old_min;
    tio.c_cc[VTIME] = old_time;

    rc = tcsetattr(fd, TCSADRAIN, &tio);
    if (rc == -1) {
        close(fd);
        return 3;
    }

    close(fd);
#endif

    // check len restrictions here
    *pulLen = strlen(pBuffer);
    if (ulMinLen != -1)
        if ((*pulLen < ulMinLen) || (*pulLen > ulMaxLen))
            return 1;

    return 0;
}

/********************************************************
 *
 * GetPassword()
 *
 *  returns size of password read, also asigne new len to pulBufferLen.
 ********************************************************/
int GetPassword(char *pPrompt, char *pPrompt2, char *pBuffer,
                int *pulBufferLen)
{
    int retVal = -1;
    int ulMinLen = -1;
    int ulMaxLen = -1;
#ifndef _WIN32
    char pBuffer2[256] = { };   //HSM's defined max pin len
#else
    char pBuffer2[256] = { '\0' };
#endif
    int ulBufferLen2 = 256;

    char *prompt = pPrompt;
    char *pBuff = pBuffer;
    int *pulBuffLen = pulBufferLen;

    ulMinLen = 1;
    ulMaxLen = 255;

    while (retVal == -1) {
        printf("\n\t%s: ", prompt);
        switch (getPswdString(pBuff, pulBuffLen, ulMinLen, ulMaxLen)) {
        case 0:
            /* ok. good to go. Either confirm the string, or return
               the string. */
            if (prompt == pPrompt2) {
                // compare new and old
                if (strcmp(pBuffer, pBuffer2) == 0)
                    retVal = *pulBufferLen;
                else {
                    printf("\n\tThe passwords are not the same.\n");
                    // reset everything so that the first password is requested again.
                    prompt = pPrompt;
                    pBuff = pBuffer;
                    pulBuffLen = pulBufferLen;
                }
            } else if (pPrompt2) {
                prompt = pPrompt2;
                pBuff = pBuffer2;
                pulBuffLen = &ulBufferLen2;
            } else
                retVal = *pulBufferLen;
            break;

        case 1:
            // we don't meet our length constraints.  loop again until we get it
            printf
                ("\n\tThe password must be between 1 and 255 characters long.\n");
            break;

        case 2:
            // this is probably a programming error
            retVal = 0;
            break;

        default:
            // 3 or higher is a problem manipulating the console
            retVal = 0;
            break;
        };
    }
    return *pulBufferLen;
}
