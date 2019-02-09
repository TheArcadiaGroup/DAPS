// This is a generated source file for Chilkat version 9.5.0.76
#ifndef _C_CkMime_H
#define _C_CkMime_H
#include "chilkatDefs.h"

#include "Chilkat_C.h"


CK_VISIBLE_PUBLIC HCkMime CkMime_Create(void);
CK_VISIBLE_PUBLIC void CkMime_Dispose(HCkMime handle);
CK_VISIBLE_PUBLIC void CkMime_getBoundary(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putBoundary(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_boundary(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getCharset(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putCharset(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_charset(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getContentType(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putContentType(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_contentType(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getCurrentDateTime(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC const char *CkMime_currentDateTime(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getDebugLogFilePath(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putDebugLogFilePath(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_debugLogFilePath(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getDisposition(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putDisposition(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_disposition(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getEncoding(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putEncoding(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_encoding(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getFilename(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putFilename(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_filename(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getLastErrorHtml(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC const char *CkMime_lastErrorHtml(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getLastErrorText(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC const char *CkMime_lastErrorText(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getLastErrorXml(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC const char *CkMime_lastErrorXml(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_getLastMethodSuccess(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putLastMethodSuccess(HCkMime cHandle, BOOL newVal);
CK_VISIBLE_PUBLIC void CkMime_getMicalg(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putMicalg(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_micalg(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getName(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putName(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_name(HCkMime cHandle);
CK_VISIBLE_PUBLIC int CkMime_getNumEncryptCerts(HCkMime cHandle);
CK_VISIBLE_PUBLIC int CkMime_getNumHeaderFields(HCkMime cHandle);
CK_VISIBLE_PUBLIC int CkMime_getNumParts(HCkMime cHandle);
CK_VISIBLE_PUBLIC int CkMime_getNumSignerCerts(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getOaepHash(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putOaepHash(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_oaepHash(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getOaepMgfHash(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putOaepMgfHash(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_oaepMgfHash(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_getOaepPadding(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putOaepPadding(HCkMime cHandle, BOOL newVal);
CK_VISIBLE_PUBLIC void CkMime_getPkcs7CryptAlg(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putPkcs7CryptAlg(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_pkcs7CryptAlg(HCkMime cHandle);
CK_VISIBLE_PUBLIC int CkMime_getPkcs7KeyLength(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putPkcs7KeyLength(HCkMime cHandle, int newVal);
CK_VISIBLE_PUBLIC void CkMime_getProtocol(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putProtocol(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_protocol(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getSigningAlg(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putSigningAlg(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_signingAlg(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_getSigningHashAlg(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC void CkMime_putSigningHashAlg(HCkMime cHandle, const char *newVal);
CK_VISIBLE_PUBLIC const char *CkMime_signingHashAlg(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_getUnwrapExtras(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putUnwrapExtras(HCkMime cHandle, BOOL newVal);
CK_VISIBLE_PUBLIC BOOL CkMime_getUseMmDescription(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putUseMmDescription(HCkMime cHandle, BOOL newVal);
CK_VISIBLE_PUBLIC BOOL CkMime_getUseXPkcs7(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putUseXPkcs7(HCkMime cHandle, BOOL newVal);
CK_VISIBLE_PUBLIC BOOL CkMime_getUtf8(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putUtf8(HCkMime cHandle, BOOL newVal);
CK_VISIBLE_PUBLIC BOOL CkMime_getVerboseLogging(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_putVerboseLogging(HCkMime cHandle, BOOL newVal);
CK_VISIBLE_PUBLIC void CkMime_getVersion(HCkMime cHandle, HCkString retval);
CK_VISIBLE_PUBLIC const char *CkMime_version(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_AddContentLength(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_AddDecryptCert(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_AddDetachedSignature(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_AddDetachedSignature2(HCkMime cHandle, HCkCert cert, BOOL transferHeaderFields);
CK_VISIBLE_PUBLIC BOOL CkMime_AddDetachedSignaturePk(HCkMime cHandle, HCkCert cert, HCkPrivateKey privateKey);
CK_VISIBLE_PUBLIC BOOL CkMime_AddDetachedSignaturePk2(HCkMime cHandle, HCkCert cert, HCkPrivateKey privateKey, BOOL transferHeaderFields);
CK_VISIBLE_PUBLIC BOOL CkMime_AddEncryptCert(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_AddHeaderField(HCkMime cHandle, const char *name, const char *value);
CK_VISIBLE_PUBLIC BOOL CkMime_AddPfxSourceData(HCkMime cHandle, HCkByteData pfxFileData, const char *pfxPassword);
CK_VISIBLE_PUBLIC BOOL CkMime_AddPfxSourceFile(HCkMime cHandle, const char *pfxFilePath, const char *password);
CK_VISIBLE_PUBLIC BOOL CkMime_AppendPart(HCkMime cHandle, HCkMime mime);
CK_VISIBLE_PUBLIC BOOL CkMime_AppendPartFromFile(HCkMime cHandle, const char *filename);
CK_VISIBLE_PUBLIC BOOL CkMime_AsnBodyToXml(HCkMime cHandle, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_asnBodyToXml(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_ClearEncryptCerts(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_ContainsEncryptedParts(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_ContainsSignedParts(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_Convert8Bit(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_ConvertToMultipartAlt(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_ConvertToMultipartMixed(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_ConvertToSigned(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_ConvertToSignedPk(HCkMime cHandle, HCkCert cert, HCkPrivateKey privateKey);
CK_VISIBLE_PUBLIC BOOL CkMime_Decrypt(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_Decrypt2(HCkMime cHandle, HCkCert cert, HCkPrivateKey privateKey);
CK_VISIBLE_PUBLIC BOOL CkMime_DecryptUsingCert(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_DecryptUsingPfxData(HCkMime cHandle, HCkByteData pfxData, const char *password);
CK_VISIBLE_PUBLIC BOOL CkMime_DecryptUsingPfxFile(HCkMime cHandle, const char *pfxFilePath, const char *pfxPassword);
CK_VISIBLE_PUBLIC BOOL CkMime_Encrypt(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_EncryptN(HCkMime cHandle);
CK_VISIBLE_PUBLIC HCkStringArray CkMime_ExtractPartsToFiles(HCkMime cHandle, const char *dirPath);
CK_VISIBLE_PUBLIC HCkCert CkMime_FindIssuer(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_GetBodyBd(HCkMime cHandle, HCkBinData binDat);
CK_VISIBLE_PUBLIC BOOL CkMime_GetBodyBinary(HCkMime cHandle, HCkByteData outData);
CK_VISIBLE_PUBLIC BOOL CkMime_GetBodyDecoded(HCkMime cHandle, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getBodyDecoded(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_GetBodyEncoded(HCkMime cHandle, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getBodyEncoded(HCkMime cHandle);
CK_VISIBLE_PUBLIC HCkCert CkMime_GetEncryptCert(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC BOOL CkMime_GetEntireBody(HCkMime cHandle, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getEntireBody(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_GetEntireHead(HCkMime cHandle, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getEntireHead(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_GetHeaderField(HCkMime cHandle, const char *fieldName, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getHeaderField(HCkMime cHandle, const char *fieldName);
CK_VISIBLE_PUBLIC BOOL CkMime_GetHeaderFieldAttribute(HCkMime cHandle, const char *name, const char *attrName, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getHeaderFieldAttribute(HCkMime cHandle, const char *name, const char *attrName);
CK_VISIBLE_PUBLIC BOOL CkMime_GetHeaderFieldName(HCkMime cHandle, int index, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getHeaderFieldName(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC BOOL CkMime_GetHeaderFieldValue(HCkMime cHandle, int index, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getHeaderFieldValue(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC BOOL CkMime_GetMime(HCkMime cHandle, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getMime(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_GetMimeBd(HCkMime cHandle, HCkBinData bindat);
CK_VISIBLE_PUBLIC BOOL CkMime_GetMimeBytes(HCkMime cHandle, HCkByteData outBytes);
CK_VISIBLE_PUBLIC BOOL CkMime_GetMimeSb(HCkMime cHandle, HCkStringBuilder sb);
CK_VISIBLE_PUBLIC HCkMime CkMime_GetPart(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC BOOL CkMime_GetSignatureSigningTime(HCkMime cHandle, int index, SYSTEMTIME *outSysTime);
CK_VISIBLE_PUBLIC BOOL CkMime_GetSignatureSigningTimeStr(HCkMime cHandle, int index, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getSignatureSigningTimeStr(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC HCkCert CkMime_GetSignerCert(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC HCkCertChain CkMime_GetSignerCertChain(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC BOOL CkMime_GetStructure(HCkMime cHandle, const char *fmt, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getStructure(HCkMime cHandle, const char *fmt);
CK_VISIBLE_PUBLIC BOOL CkMime_GetXml(HCkMime cHandle, HCkString outStr);
CK_VISIBLE_PUBLIC const char *CkMime_getXml(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_HasSignatureSigningTime(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC BOOL CkMime_IsApplicationData(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsAttachment(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsAudio(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsEncrypted(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsHtml(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsImage(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsMultipart(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsMultipartAlternative(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsMultipartMixed(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsMultipartRelated(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsPlainText(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsSigned(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsText(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsUnlocked(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsVideo(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_IsXml(HCkMime cHandle);
CK_VISIBLE_PUBLIC HCkJsonObject CkMime_LastJsonData(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_LoadMime(HCkMime cHandle, const char *mimeMsg);
CK_VISIBLE_PUBLIC BOOL CkMime_LoadMimeBd(HCkMime cHandle, HCkBinData bindat);
CK_VISIBLE_PUBLIC BOOL CkMime_LoadMimeBytes(HCkMime cHandle, HCkByteData binData);
CK_VISIBLE_PUBLIC BOOL CkMime_LoadMimeFile(HCkMime cHandle, const char *fileName);
CK_VISIBLE_PUBLIC BOOL CkMime_LoadMimeSb(HCkMime cHandle, HCkStringBuilder sb);
CK_VISIBLE_PUBLIC BOOL CkMime_LoadXml(HCkMime cHandle, const char *xml);
CK_VISIBLE_PUBLIC BOOL CkMime_LoadXmlFile(HCkMime cHandle, const char *fileName);
CK_VISIBLE_PUBLIC BOOL CkMime_NewMessageRfc822(HCkMime cHandle, HCkMime mimeObject);
CK_VISIBLE_PUBLIC BOOL CkMime_NewMultipartAlternative(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_NewMultipartMixed(HCkMime cHandle);
CK_VISIBLE_PUBLIC BOOL CkMime_NewMultipartRelated(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_RemoveHeaderField(HCkMime cHandle, const char *fieldName, BOOL bAllOccurrences);
CK_VISIBLE_PUBLIC BOOL CkMime_RemovePart(HCkMime cHandle, int index);
CK_VISIBLE_PUBLIC BOOL CkMime_SaveBody(HCkMime cHandle, const char *filename);
CK_VISIBLE_PUBLIC BOOL CkMime_SaveLastError(HCkMime cHandle, const char *path);
CK_VISIBLE_PUBLIC BOOL CkMime_SaveMime(HCkMime cHandle, const char *filename);
CK_VISIBLE_PUBLIC BOOL CkMime_SaveXml(HCkMime cHandle, const char *filename);
CK_VISIBLE_PUBLIC void CkMime_SetBody(HCkMime cHandle, const char *str);
CK_VISIBLE_PUBLIC BOOL CkMime_SetBodyFromBinary(HCkMime cHandle, HCkByteData binData);
CK_VISIBLE_PUBLIC BOOL CkMime_SetBodyFromEncoded(HCkMime cHandle, const char *encoding, const char *str);
CK_VISIBLE_PUBLIC BOOL CkMime_SetBodyFromFile(HCkMime cHandle, const char *fileName);
CK_VISIBLE_PUBLIC BOOL CkMime_SetBodyFromHtml(HCkMime cHandle, const char *str);
CK_VISIBLE_PUBLIC BOOL CkMime_SetBodyFromPlainText(HCkMime cHandle, const char *str);
CK_VISIBLE_PUBLIC BOOL CkMime_SetBodyFromXml(HCkMime cHandle, const char *str);
#if defined(CK_CSP_INCLUDED)
CK_VISIBLE_PUBLIC BOOL CkMime_SetCSP(HCkMime cHandle, HCkCsp csp);
#endif
CK_VISIBLE_PUBLIC BOOL CkMime_SetHeaderField(HCkMime cHandle, const char *name, const char *value);
CK_VISIBLE_PUBLIC BOOL CkMime_SetVerifyCert(HCkMime cHandle, HCkCert cert);
CK_VISIBLE_PUBLIC BOOL CkMime_UnlockComponent(HCkMime cHandle, const char *unlockCode);
CK_VISIBLE_PUBLIC BOOL CkMime_UnwrapSecurity(HCkMime cHandle);
CK_VISIBLE_PUBLIC void CkMime_UrlEncodeBody(HCkMime cHandle, const char *charset);
CK_VISIBLE_PUBLIC BOOL CkMime_UseCertVault(HCkMime cHandle, HCkXmlCertVault vault);
CK_VISIBLE_PUBLIC BOOL CkMime_Verify(HCkMime cHandle);
#endif
