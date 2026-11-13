/*
 * JNI shim for libanubis_solver.
 *
 * JDK 21 still has java.lang.foreign in preview, and JNA would add a dependency,
 * so this is a plain JNI shim: it compiles with any JDK's headers and works from
 * Java 8 to 25 with no flags and no jars.
 *
 * Convention: every native returns the C status code, and writes its outputs
 * into caller-supplied arrays. The Java layer in Anubis.java turns a non-zero
 * status into an exception, so nothing is thrown from C.
 *
 * Build: see bindings/java/Makefile (javac -h produces the header this matches).
 */
/* the header javac -h generates; including it makes the JNI signatures
 * compile-time checked instead of silently mismatched at runtime */
#include "io_github_celikfana_anubis_Anubis.h"
#include <stdint.h>
#include <string.h>

#include "anubis-solver.h"

#define FN(name) Java_io_github_celikfana_anubis_Anubis_##name

/* copy a NUL-terminated C string into caller storage, always NUL terminated */
static void copy_out(char *dst, jsize cap, const char *src)
{
    if (cap <= 0 || dst == NULL) return;
    if (src == NULL) {
        dst[0] = 0;
        return;
    }
    jsize n = (jsize)strlen(src);
    if (n > cap - 1) n = cap - 1;
    memcpy(dst, src, (size_t)n);
    dst[n] = 0;
}

/* ------------------------------------------------------------- introspection */

JNIEXPORT jstring JNICALL FN(nativeVersion)(JNIEnv *env, jclass cls)
{
    (void)cls;
    return (*env)->NewStringUTF(env, anubis_solver_version());
}

JNIEXPORT jstring JNICALL FN(nativeGpuInfo)(JNIEnv *env, jclass cls)
{
    const char *g = anubis_gpu_info();
    (void)cls;
    return g ? (*env)->NewStringUTF(env, g) : NULL;
}

JNIEXPORT jint JNICALL FN(nativeDefaultThreads)(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)anubis_default_threads();
}

JNIEXPORT jstring JNICALL FN(nativeAffinityInfo)(JNIEnv *env, jclass cls)
{
    const char *a = anubis_cpu_affinity_info();
    (void)cls;
    return a ? (*env)->NewStringUTF(env, a) : NULL;
}

JNIEXPORT jint JNICALL FN(nativeBatchWidth)(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return (jint)anubis_batch_width();
}

JNIEXPORT void JNICALL FN(nativeSetGpuVerify)(JNIEnv *env, jclass cls, jboolean enable)
{
    (void)env; (void)cls;
    anubis_set_gpu_verify(enable == JNI_TRUE ? 1 : 0);
}

JNIEXPORT jboolean JNICALL FN(nativeGpuVerify)(JNIEnv *env, jclass cls)
{
    (void)env; (void)cls;
    return anubis_gpu_verify() ? JNI_TRUE : JNI_FALSE;
}

/* --------------------------------------------------------------- sha256 utils */

JNIEXPORT jstring JNICALL FN(nativeSha256Hex)(JNIEnv *env, jclass cls, jbyteArray data)
{
    char out[65];
    jsize len;
    jbyte *bytes;
    const char *result;

    (void)cls;
    if (data == NULL) {
        jclass ex = (*env)->FindClass(env, "java/lang/NullPointerException");
        (*env)->ThrowNew(env, ex, "data");
        return NULL;
    }
    len = (*env)->GetArrayLength(env, data);
    bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) return NULL;

    memset(out, 0, sizeof out);
    /* anubis_sha256_hex takes a length, so zero-length input is fine */
    int rc = anubis_sha256_hex((const char *)bytes, (size_t)len, out);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    if (rc != ANUBIS_OK) return NULL;

    return (*env)->NewStringUTF(env, out);
}

JNIEXPORT jlongArray JNICALL FN(nativeSha256Midstate)(JNIEnv *env, jclass cls, jbyteArray data)
{
    uint32_t words[8];
    jlong vals[8];
    jlongArray out;
    jsize len;
    jbyte *bytes;

    (void)cls;
    if (data == NULL) return NULL;
    len = (*env)->GetArrayLength(env, data);
    bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) return NULL;

    int rc = anubis_sha256_midstate((const char *)bytes, (size_t)len, words);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    if (rc != ANUBIS_OK) return NULL;

    for (int i = 0; i < 8; i++) vals[i] = (jlong)words[i]; /* unsigned in a long */
    out = (*env)->NewLongArray(env, 8);
    if (out == NULL) return NULL;
    (*env)->SetLongArrayRegion(env, out, 0, 8, vals);
    return out;
}

/* ------------------------------------------------------------------- solving */

/* shared body for the four solve entry points */
static jint solve_common(JNIEnv *env, jstring challenge, jint difficulty, jint threads,
                         jlong max_nonce, jdouble budget_ms, jlongArray out_nonce,
                         jbyteArray out_hex, jdoubleArray out_ms, int family)
{
    const char *ch;
    jlong nonce64 = 0;
    uint32_t nonce32 = 0;
    double ms = 0.0;
    char hex[65];
    int rc;

    if (challenge == NULL || out_nonce == NULL || out_hex == NULL) return ANUBIS_ERR_ARG;
    ch = (*env)->GetStringUTFChars(env, challenge, NULL);
    if (ch == NULL) return ANUBIS_ERR_ARG;
    memset(hex, 0, sizeof hex);

    switch (family) {
    case 0: /* fast / slow */
        rc = anubis_solve_nibbles(ch, (int)difficulty, (int)threads,
                                  (int64_t)max_nonce, (double)budget_ms,
                                  (uint64_t *)&nonce64, hex, &ms);
        break;
    case 1:
        rc = anubis_solve_bits(ch, (int)difficulty, (int)threads, (double)budget_ms,
                               &nonce32, hex, &ms);
        break;
    case 2:
        rc = anubis_solve_argon2id(ch, (int)difficulty, (int)threads, (double)budget_ms,
                                   &nonce32, hex, &ms);
        break;
    default:
        rc = anubis_solve_hashx(ch, (int)difficulty, (int)threads, (double)budget_ms,
                                &nonce32, hex, &ms);
        break;
    }
    (*env)->ReleaseStringUTFChars(env, challenge, ch);
    if (rc != ANUBIS_OK) return rc;

    /* 64-bit nonces go out unchanged; 32-bit ones are widened */
    jlong value = (family == 0) ? nonce64 : (jlong)nonce32;
    (*env)->SetLongArrayRegion(env, out_nonce, 0, 1, &value);

    jbyte hexbuf[65];
    for (int i = 0; i < 65; i++) hexbuf[i] = (jbyte)hex[i];
    (*env)->SetByteArrayRegion(env, out_hex, 0, 65, hexbuf);

    if (out_ms != NULL) (*env)->SetDoubleArrayRegion(env, out_ms, 0, 1, &ms);
    return ANUBIS_OK;
}

JNIEXPORT jint JNICALL FN(nativeSolveNibbles)(JNIEnv *env, jclass cls, jstring challenge,
                                              jint difficulty, jint threads, jlong maxNonce,
                                              jdouble budgetMs, jlongArray outNonce,
                                              jbyteArray outHex, jdoubleArray outMs)
{
    (void)cls;
    return solve_common(env, challenge, difficulty, threads, maxNonce, budgetMs,
                        outNonce, outHex, outMs, 0);
}

JNIEXPORT jint JNICALL FN(nativeSolveBits)(JNIEnv *env, jclass cls, jstring challengeHex,
                                           jint difficulty, jint threads, jdouble budgetMs,
                                           jlongArray outNonce, jbyteArray outHex,
                                           jdoubleArray outMs)
{
    (void)cls;
    return solve_common(env, challengeHex, difficulty, threads, -1, budgetMs,
                        outNonce, outHex, outMs, 1);
}

JNIEXPORT jint JNICALL FN(nativeSolveArgon2id)(JNIEnv *env, jclass cls, jstring challengeHex,
                                               jint difficulty, jint threads, jdouble budgetMs,
                                               jlongArray outNonce, jbyteArray outHex,
                                               jdoubleArray outMs)
{
    (void)cls;
    return solve_common(env, challengeHex, difficulty, threads, -1, budgetMs,
                        outNonce, outHex, outMs, 2);
}

JNIEXPORT jint JNICALL FN(nativeSolveHashx)(JNIEnv *env, jclass cls, jstring challengeHex,
                                            jint difficulty, jint threads, jdouble budgetMs,
                                            jlongArray outNonce, jbyteArray outHex,
                                            jdoubleArray outMs)
{
    (void)cls;
    return solve_common(env, challengeHex, difficulty, threads, -1, budgetMs,
                        outNonce, outHex, outMs, 3);
}

/* ----------------------------------------------------------------- verifying */

static jint verify_common(JNIEnv *env, jstring challenge, jlong nonce, jint difficulty,
                          jbyteArray out_hex, int family)
{
    const char *ch;
    char hex[65];
    int rc;

    if (challenge == NULL || out_hex == NULL) return ANUBIS_ERR_ARG;
    ch = (*env)->GetStringUTFChars(env, challenge, NULL);
    if (ch == NULL) return ANUBIS_ERR_ARG;
    memset(hex, 0, sizeof hex);

    switch (family) {
    case 0: rc = anubis_verify_nibbles(ch, (uint64_t)nonce, (int)difficulty, hex); break;
    case 1: rc = anubis_verify_bits(ch, (uint32_t)nonce, (int)difficulty, hex); break;
    case 2: rc = anubis_verify_argon2id(ch, (uint32_t)nonce, (int)difficulty, hex); break;
    default: rc = anubis_verify_hashx(ch, (uint32_t)nonce, (int)difficulty, hex); break;
    }
    (*env)->ReleaseStringUTFChars(env, challenge, ch);

    jbyte hexbuf[65];
    for (int i = 0; i < 65; i++) hexbuf[i] = (jbyte)hex[i];
    (*env)->SetByteArrayRegion(env, out_hex, 0, 65, hexbuf);
    return rc;
}

JNIEXPORT jint JNICALL FN(nativeVerifyNibbles)(JNIEnv *env, jclass cls, jstring challenge,
                                               jlong nonce, jint difficulty, jbyteArray outHex)
{
    (void)cls;
    return verify_common(env, challenge, nonce, difficulty, outHex, 0);
}

JNIEXPORT jint JNICALL FN(nativeVerifyBits)(JNIEnv *env, jclass cls, jstring challengeHex,
                                            jlong nonce, jint difficulty, jbyteArray outHex)
{
    (void)cls;
    return verify_common(env, challengeHex, nonce, difficulty, outHex, 1);
}

JNIEXPORT jint JNICALL FN(nativeVerifyArgon2id)(JNIEnv *env, jclass cls, jstring challengeHex,
                                                jlong nonce, jint difficulty, jbyteArray outHex)
{
    (void)cls;
    return verify_common(env, challengeHex, nonce, difficulty, outHex, 2);
}

JNIEXPORT jint JNICALL FN(nativeVerifyHashx)(JNIEnv *env, jclass cls, jstring challengeHex,
                                             jlong nonce, jint difficulty, jbyteArray outHex)
{
    (void)cls;
    return verify_common(env, challengeHex, nonce, difficulty, outHex, 3);
}
