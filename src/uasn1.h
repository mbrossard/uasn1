#ifndef UASN1_H
#define UASN1_H

#include <stdlib.h>

/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

/** @file asn1.h
 * General definitions for the library.
 *
 * This file contains the definition of uasn1_item_t (and its
 * substructure), uasn1_buffer_t as well as the base encoding
 * functions.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * uasn1_type_t
 */
typedef enum {
    /** EndOfContent */
    uasn1_end_of_content           = 0x00,
    /** Boolean */
    uasn1_boolean_type             = 0x01,
    /** Integer */
    uasn1_integer_type             = 0x02,
    /** BitString */
    uasn1_bit_string_type          = 0x03,
    /** OctetString */
    uasn1_octet_string_type        = 0x04,
    /** Null */
    uasn1_null_type                = 0x05,
    /** Object Identifier */
    uasn1_oid_type                 = 0x06,
    /** Object Descriptor */
    uasn1_object_descriptor_type   = 0x07,
    /** External */
    uasn1_external_type            = 0x08,
    /** Real */
    uasn1_real_type                = 0x09,
    /** Enumerated */
    uasn1_enumerated_type          = 0x0A,
    /** UTF8String */
    uasn1_utf8_string_type         = 0x0C,
    /** Sequence */
    uasn1_sequence_type            = 0x10,
    /** Set */
    uasn1_set_type                 = 0x11,
    /** NumericString */
    uasn1_numeric_string_type      = 0x12,
    /** PrintableString */
    uasn1_printable_string_type    = 0x13,
    /** TeletextString */
    uasn1_teletext_string_type     = 0x14,
    /** VideotexString */
    uasn1_videotex_string_type     = 0x15,
    /** IA5String */
    uasn1_ia5_string_type          = 0x16,
    /** UTCTime */
    uasn1_utc_time_type            = 0x17,
    /** GeneralizedTime */
    uasn1_generalized_time_type    = 0x18,
    /** GraphicString */
    uasn1_graphic_string_type      = 0x19,
    /** VisibleString */
    uasn1_visible_string_type      = 0x1A,
    /** GeneralString */
    uasn1_general_string_type      = 0x1B,
    /** UniversalString */
    uasn1_universal_string_type    = 0x1C,
    /** BMPString */
    uasn1_bmp_string_type          = 0x1E
} uasn1_type_t;

/**
 * uasn1_construct_t
 */
typedef enum {
    /** Primitive Tag */
    uasn1_primitive_tag            = 0x0,
    /** Constructed Tag */
    uasn1_constructed_tag          = 0x20
} uasn1_construct_t;

/**
 * uasn1_class_t
 */
typedef enum {
    /** Universal Class */
    uasn1_universal_tag            = 0x0,
    /** Application Class */
    uasn1_application_tag          = 0x40,
    /** Context Specific Class */
    uasn1_context_specific_tag     = 0x80,
    /** Private Class */
    uasn1_private_tag              = 0xC0,
    /** Class Mask */
    uasn1_class_mask               = 0xC0
} uasn1_class_t;

/**
 * uasn1_tagging_class_t
 */
typedef enum {
    /** No Tagging */
    uasn1_no_tag                   = 0x0,
    /** Implicit Tagging */
    uasn1_implicit_tag             = 0x1,
    /** Explicit Tagging */
    uasn1_explicit_tag             = 0x2
} uasn1_tagging_class_t;

/**
 * uasn1_flags_t
 */
typedef enum {
    /** Regular Type */
	uasn1_regular_type             = 0x00,
    /** Pre-encoded Type */
	uasn1_preencoded_type          = 0x01,
    /** Choice Type */
	uasn1_choice_type              = 0x02,
    /** Optionnal Type */
	uasn1_optional_type            = 0x04,
    /** Optionnal Type */
	uasn1_indefinite_type          = 0x08
} uasn1_flags_t;

/**
 * uasn1_boolean_t
 */
typedef enum {
    /** Boolean False */
    uasn1_false                    = 0x0,
    /** Boolean True */
    uasn1_true                     = 0xFF
} uasn1_boolean_t;

#ifndef OPTIMIZE
/**
 * @brief Tag description structure
 */
typedef struct {
    /** @brief Primitive type see @ref uasn1_type_t */
    uasn1_type_t type;
    /** construct Constructed or Primitive */
    uasn1_construct_t construct;
    /** class Universal, Application, Context Specific or Private */
    uasn1_class_t _class;
    /** tagging : None, Explicit, Implicit */
    uasn1_tagging_class_t tag;
    /** value of the tag */
    unsigned char value;
    /** flags : Preencoded, Choice, Optional, Indefinite */
    uasn1_flags_t flags;
} uasn1_tag_t;
#else
/* Doing this will save space */
typedef struct {
    unsigned char type;
    unsigned char construct;
    unsigned char _class;
    unsigned char tag;
    unsigned char value;
    unsigned char flags;
} uasn1_tag_t;
#endif

/**
 * List structure
 */
typedef struct uasn1_item_t uasn1_item_t;

/**
 * Array structure
 */
typedef struct {
    /** Array of elements  */
    uasn1_item_t **elements;
    /** Allocated size */
    unsigned int  size;
    /** Index of next element */
    unsigned int  next;
} uasn1_array_t;

/**
 * String structure
 */
typedef struct {
    /** String value */
    unsigned char *string;
    /** String size */
    size_t size;
    /** String flag (for BitString) */
    unsigned int flags;
} uasn1_string_t;

/**
 * Object Identifier structure
 */
typedef struct {
    /** OID element array */
    unsigned int *elements;
    /** Number of elements */
    size_t size;
} uasn1_oid_t;

/**
 * Value structure
 */
typedef union {
    /** Numeric value (Boolean) */
    int               numeric;
    /** List (Sequence and Set) */
    uasn1_array_t     list;
    /** Strings, Integer and unsupported types */
    uasn1_string_t    string;
    /** Object Identifiers */
    uasn1_oid_t       oid;
} uasn1_value_t;

/**
 * This is the base element of the library.
 */
struct uasn1_item_t {
    /** Tag of the element */
    uasn1_tag_t   tag;
    /** Value of the element */
    uasn1_value_t value;
};

/**
 * Buffer structure
 */
typedef struct {
    /** Size of the allocated memory */
    size_t size;
    /** Current offset for writing */
    unsigned int current;
    /** Current offset for reading */
    unsigned int seek;
    /** Allocated memory */
    unsigned char *buffer;
} uasn1_buffer_t;

/**
 * Allocates a new uasn1_item_t.
 *
 * @return the new uasn1_item_t or NULL if allocation failed.
 */
uasn1_item_t *uasn1_item_new(uasn1_type_t type);

/** Creates a new uasn1_item_t of string type */
uasn1_item_t *uasn1_string_new(uasn1_type_t type, void *string, size_t size);

/** Creates a new bit string */
inline static uasn1_item_t *uasn1_bit_string_new(void *string, size_t size,
                                                 unsigned int flags) {
    uasn1_item_t *e = uasn1_string_new(uasn1_bit_string_type, string, size);
    if(e) {
        e->value.string.flags = flags;
    }
    return e;
}

#define uasn1_octet_string_new(str, l) \
    uasn1_string_new(uasn1_octet_string_type, str, l)
#define uasn1_utf8_string_new(str, l) \
    uasn1_string_new(uasn1_utf8_string_type, str, l)
#define uasn1_printable_string_new(str, l) \
    uasn1_string_new(uasn1_printable_string_type, str, l)
#define uasn1_ia5_string_new(str, l) \
    uasn1_string_new(uasn1_ia5_string_type, str, l)
#define uasn1_generalized_time_new(str, l) \
    uasn1_string_new(uasn1_generalized_time_type, str, l)
#define uasn1_utc_time_new(str, l) \
    uasn1_string_new(uasn1_utc_time_type, str, l)

/** Creates a new ASN1Element of type Object Identifier */
uasn1_item_t *uasn1_oid_new(unsigned int *elements, size_t size);

/** Creates a new Integer */
uasn1_item_t *uasn1_natural_new(uasn1_type_t type, int i);

#define uasn1_integer_new(i) \
    uasn1_natural_new(uasn1_integer_type, i)
#define uasn1_enumerated_new(i) \
    uasn1_natural_new(uasn1_enumerated_type, i)

/** Creates a new uasn1_item_t of integer type */
uasn1_item_t *uasn1_large_integer_new(uasn1_type_t type, void *string, size_t size);

/** Creates a new boolean uasn1_item_t element */
inline static uasn1_item_t *uasn1_boolean_new(uasn1_boolean_t b)
{
    uasn1_item_t *e = uasn1_item_new(uasn1_boolean_type);
    if(e) {
        e->value.numeric = b;
    }
    return e;
}

/** Creates a new list */
uasn1_item_t *uasn1_array_new(uasn1_type_t type, size_t size);

/** Creates a new ASN1 Sequence */
inline static uasn1_item_t *uasn1_sequence_new(int size) {
    return uasn1_array_new(uasn1_sequence_type, size);
}
/** Creates a new ASN1 Set */
inline static uasn1_item_t *uasn1_set_new(int size) {
    return uasn1_array_new(uasn1_set_type, size);
}

/** Add an element in a list */
int uasn1_add(uasn1_item_t *list, uasn1_item_t *element);

/** Gets the count of elements */
inline static unsigned int uasn1_count(uasn1_item_t *list)
{
    return (list) ? list->value.list.next : 0;
}

/** Gets the element at index */
inline static uasn1_item_t *uasn1_get(uasn1_item_t *list,
                                      unsigned int index)
{
	return (list && list->value.list.elements &&
            list->value.list.next >= index) ?
        ((list->value).list.elements)[index] : NULL;
}

inline static uasn1_item_t *uasn1_set_tag(uasn1_item_t *element,
                                          unsigned char _class,
                                          unsigned char value,
                                          unsigned char tag)
{
    /* Size check */
    element->tag._class = _class;
    element->tag.value = value;
    element->tag.tag = tag;
    return element;
}

/** Adds an element if non null with tag value */
inline static void uasn1_add_tagged(uasn1_item_t *list,
                                    uasn1_item_t *element,
                                    unsigned char tag,
                                    unsigned char value,
                                    unsigned char tagging)
{
    if((element != NULL) && (list != NULL)) {
        uasn1_set_tag(element, tag, value, tagging);
        uasn1_add(list, element);
    }
}

inline static uasn1_item_t *uasn1_set_flags(uasn1_item_t *element,
                                            uasn1_flags_t flags)
{
    element->tag.flags |= flags;
    return element;
}

/**
 * Frees an ASN1 tree
 */
void uasn1_free(uasn1_item_t *element);

/** Creates a new Buffer */
uasn1_buffer_t *uasn1_buffer_new(size_t size);

/** Frees a Buffer */
void uasn1_buffer_free(uasn1_buffer_t *buffer);

/** Creates a pre-encoded element from the content of the buffer. */
uasn1_item_t *uasn1_preencoded(uasn1_buffer_t *buffer);

/** Write a Buffer to a file */
int uasn1_write_buffer(uasn1_buffer_t *buffer, char *filename);
/** Read a buffer from a file */
int uasn1_load_buffer(uasn1_buffer_t *buffer, char *filename);

/** Reallocate a buffer */
int uasn1_buffer_reserve(uasn1_buffer_t *buffer, size_t size);

/** Add a string to a buffer */
int uasn1_buffer_push(uasn1_buffer_t *buffer, void *ptr, size_t size);

/** Add a byte to a buffer */
int uasn1_buffer_put(uasn1_buffer_t *buffer, unsigned char c);

/** Get a byte from a buffer */
unsigned char uasn1_buffer_get(uasn1_buffer_t *buffer);

/** Get a string from a buffer */
int uasn1_buffer_pop(uasn1_buffer_t *buffer, void* ptr, size_t size);

/**
 * @brief Decodes DER-encoded ASN.1
 * @param [in] buffer   Buffer to read DER data.
 * @return decoded ASN1 structure if successful
 * @return @c NULL otherwise
 */
uasn1_item_t *uasn1_decode(uasn1_buffer_t *buffer);

/**
 * @brief Encodes ASN.1 structure to DER
 * @param [in]  element  Pointer to ASN.1 structure to encode.
 * @param [out] buffer   Buffer in which store the DER representation.
 * @return 0 if successful
 * @return -1 if failure
 */
int uasn1_encode(uasn1_item_t *element,
                 uasn1_buffer_t *buffer);

/** uasn1_to_octet_string */
uasn1_item_t *uasn1_to_octet_string(uasn1_item_t *element);

#ifdef __cplusplus
}
#endif

#endif
