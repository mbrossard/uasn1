/*
 * Copyright © 2015 Mathias Brossard
 */

#include "tsa.h"
#include "uasn1.h"
#include "x509.h"

uasn1_item_t *uasn1_tsa_attribute(uasn1_item_t *oid,
                                  uasn1_item_t *content)
{
    uasn1_item_t *attribute = uasn1_sequence_new(2);
    uasn1_item_t *value = uasn1_set_new(1);

    uasn1_add(value, content);
    uasn1_add(attribute, oid);
    uasn1_add(attribute, value);
    return attribute;
}

uasn1_item_t *uasn1_tsa_imprint(uasn1_digest_t digest,
                                uasn1_item_t *hash)
{
    uasn1_item_t *imprint = uasn1_sequence_new(2);
    uasn1_item_t *algoid = uasn1_sequence_new(2);
    uasn1_item_t *oid = uasn1_digest_oid(digest);

    uasn1_add(algoid, oid);
    uasn1_add(algoid, uasn1_item_new(uasn1_null_type));
    uasn1_add(imprint, algoid);
    uasn1_add(imprint, hash);
    return imprint;
}

uasn1_item_t *uasn1_tsa_request(uasn1_item_t *imprint,
                                uasn1_item_t *policy,
                                uasn1_item_t *nonce,
                                uasn1_item_t *certReq,
                                uasn1_item_t *extensions)
{
    uasn1_item_t *seq = uasn1_sequence_new(6);
    uasn1_add(seq, uasn1_integer_new(1));
    uasn1_add(seq, imprint);
    if(policy) {
        uasn1_add(seq, policy);
    }
    if(nonce) {
        uasn1_add(seq, nonce);
    }
    if(certReq) {
        uasn1_add(seq, certReq);
    }
    if(extensions) {
        uasn1_add_tagged(seq, extensions, uasn1_context_specific_tag,
                         0, uasn1_explicit_tag);
    }
    return seq;
}

uasn1_item_t *uasn1_tstinfo(uasn1_item_t *policy,
                            uasn1_item_t *imprint,
                            uasn1_item_t *serial,
                            uasn1_item_t *time,
                            uasn1_item_t *accuracy,
                            uasn1_item_t *ordering,
                            uasn1_item_t *nonce,
                            uasn1_item_t *tsa,
                            uasn1_item_t *extensions)
{
    uasn1_item_t *tstinfo = uasn1_sequence_new(10);

    uasn1_add(tstinfo, uasn1_integer_new(1));
    uasn1_add(tstinfo, policy);
    uasn1_add(tstinfo, imprint);
    uasn1_add(tstinfo, serial);
    uasn1_add(tstinfo, time);

    if(accuracy) {
        uasn1_add(tstinfo, accuracy);
    }
    if(ordering) {
        uasn1_add(tstinfo, ordering);
    }
    if(nonce) {
        uasn1_add(tstinfo, nonce);
    }

    if(tsa) {
        uasn1_add_tagged(tstinfo, tsa, uasn1_context_specific_tag,
                         0, uasn1_explicit_tag);
    }
    if(extensions) {
        uasn1_add_tagged(tstinfo, extensions, uasn1_context_specific_tag,
                         1, uasn1_implicit_tag);
    }
    return tstinfo;
}

uasn1_item_t *uasn1_signed_data(uasn1_item_t *version,
                                uasn1_item_t *digestAlgorithm,
                                uasn1_item_t *encapsulatedInfo,
                                uasn1_item_t *certificates,
                                uasn1_item_t *crls,
                                uasn1_item_t *signerInfos)
{
    uasn1_item_t *signeddata = uasn1_sequence_new(6);
    uasn1_item_t *digestAlgorithms = uasn1_set_new(1);
    uasn1_add(digestAlgorithms, digestAlgorithm);

    uasn1_add(signeddata, version);
    uasn1_add(signeddata, digestAlgorithms);
    uasn1_add(signeddata, encapsulatedInfo);
    if(certificates) {
        uasn1_set_tag(certificates, uasn1_context_specific_tag,
                      0, uasn1_implicit_tag);
        uasn1_add(signeddata, certificates);
    }
    if(crls) {
        uasn1_set_tag(crls, uasn1_context_specific_tag,
                      1, uasn1_implicit_tag);
        uasn1_add(signeddata, crls);
    }
    uasn1_add(signeddata, signerInfos);
    return signeddata;
}

uasn1_item_t *uasn1_timestamp_response(int status,
                                       uasn1_item_t *statusString,
                                       uasn1_item_t *failInfo,
                                       uasn1_item_t *data)
{
    unsigned int id_signedData[7] = { 1, 2, 840, 113549, 1, 7, 2 };
    uasn1_item_t *tsr = uasn1_sequence_new(2);
    uasn1_item_t *info = uasn1_sequence_new(3);
    uasn1_item_t *content = uasn1_sequence_new(2);

    uasn1_add(info, uasn1_integer_new(status));
    uasn1_add(info, statusString);
    uasn1_add(info, failInfo);
    uasn1_add(tsr, info);

    if(data) {
        uasn1_add(content, uasn1_oid_new(id_signedData, 7));
        uasn1_add(content, data);
        uasn1_add(tsr, content);
	}

    return tsr;

}

uasn1_item_t *uasn1_tsa_response(uasn1_item_t *tstinfo,
                                 uasn1_digest_t digest,
                                 uasn1_item_t *time,
                                 uasn1_buffer_t *crt,
                                 uasn1_crypto_t *crypto,
                                 uasn1_key_t *key)
{
    unsigned int id_ct_TSTInfo[9] = { 1, 2, 840, 113549, 1, 9, 16, 1, 4 };
    uasn1_buffer_t *buffer = uasn1_buffer_new(64);
    uasn1_item_t *signed_data = uasn1_sequence_new(6);
    uasn1_item_t *encapsulatedInfo = uasn1_sequence_new(2);
    uasn1_item_t *algoid = uasn1_sequence_new(2);
    uasn1_item_t *signerinfo = uasn1_sequence_new(5);
    uasn1_item_t *signerid = uasn1_sequence_new(2);
    uasn1_item_t *signedattrs = uasn1_set_new(4);
    uasn1_item_t *infoset = uasn1_set_new(1);
    uasn1_item_t *content_type, *to_digest, *signature;
    uasn1_item_t *crthash, *x509, *dn, *serial;
    unsigned int idContentType[7]   = { 1, 2, 840, 113549, 1, 9, 3 };
    unsigned int idMessageDigest[7] = { 1, 2, 840, 113549, 1, 9, 4 };
    unsigned int idSigningTime[7]   = { 1, 2, 840, 113549, 1, 9, 5 };
    unsigned int idEssCertId[9] = { 1, 2, 840, 113549, 1, 9, 16, 2, 12 };

    content_type = uasn1_oid_new(id_ct_TSTInfo, 9);
    to_digest = uasn1_to_octet_string(tstinfo);
    uasn1_add(encapsulatedInfo, content_type);
    uasn1_add(encapsulatedInfo, uasn1_set_tag(to_digest,
                                              uasn1_context_specific_tag,
                                              0, uasn1_explicit_tag));

    crthash = uasn1_hash_buffer_to_octet_string(crypto, digest, crt);
    x509 = uasn1_decode(crt);
    dn = uasn1_x509_get_issuer(uasn1_x509_get_tbs(x509));
    serial = uasn1_x509_get_serial(uasn1_x509_get_tbs(x509));

    uasn1_add(signerinfo, uasn1_integer_new(1));
    uasn1_add(signerid, dn);
    uasn1_add(signerid, serial);

    uasn1_add(signedattrs,
              uasn1_tsa_attribute(uasn1_oid_new(idContentType, 7),
                                  content_type));
    uasn1_add(signedattrs,
              uasn1_tsa_attribute(uasn1_oid_new(idSigningTime, 7),
                                  time));

    uasn1_add(signedattrs,
              uasn1_tsa_attribute(uasn1_oid_new(idMessageDigest, 7),
                                  uasn1_hash_to_octet_string(crypto, digest, to_digest)));

    if(crthash && 0) {
        uasn1_item_t *seq1 = uasn1_sequence_new(1);
        uasn1_item_t *seq2 = uasn1_sequence_new(1);
        uasn1_item_t *seq3 = uasn1_sequence_new(1);
        uasn1_add(seq1, seq2);
        uasn1_add(seq2, seq3);
        uasn1_add(seq3, crthash);
        uasn1_add(signedattrs,
                  uasn1_tsa_attribute(uasn1_oid_new(idEssCertId, 9),
                                      seq1));
    }

    uasn1_encode(signedattrs, buffer);
    signature = uasn1_key_x509_sign(key, digest, buffer);
    signature->tag.type = uasn1_octet_string_type;

    uasn1_set_tag(signedattrs, uasn1_context_specific_tag,
                  0, uasn1_implicit_tag);

    uasn1_add(algoid, uasn1_digest_oid(digest));
    uasn1_add(algoid, uasn1_item_new(uasn1_null_type));

    uasn1_add(signerinfo, signerid);
    uasn1_add(signerinfo, algoid);
    uasn1_add(signerinfo, signedattrs);
    uasn1_add(signerinfo, uasn1_x509_algorithm2(key, digest));
    uasn1_add(signerinfo, signature);
    uasn1_add(infoset, signerinfo);

    algoid = uasn1_sequence_new(2);
    uasn1_add(algoid, uasn1_digest_oid(digest));
    uasn1_add(algoid, uasn1_item_new(uasn1_null_type));

    signed_data = uasn1_signed_data(uasn1_integer_new(3), algoid,
                                    encapsulatedInfo, NULL, NULL, infoset);
    uasn1_set_tag(signed_data, uasn1_context_specific_tag,
                  0, uasn1_explicit_tag);

    return uasn1_timestamp_response(0, NULL, NULL, signed_data);
}
