#include "smolcert.h"
#include "cbor.h"

#include <stdlib.h>

sc_error_t expect_byte_string(CborValue *it, uint8_t** buf, size_t* buf_len);
sc_error_t expect_fixed_length_bytes(CborValue* it, uint8_t* buf, size_t exp_buf_len);
sc_error_t expect_string(CborValue* it, char** buf, size_t* buf_len);
sc_error_t expect_boolean(CborValue* it, bool* val);
sc_error_t expect_uint64_t(CborValue* it, uint64_t* val);
sc_error_t parse_validity(CborValue* it, sc_validity_t* validity);
sc_error_t parse_extension(CborValue *it, sc_extension_t* extension);
sc_error_t parse_extensions(CborValue *it, sc_extension_t** extensions, size_t* extensions_len);

sc_error_t sc_parse_certificate(const uint8_t* buffer, size_t size, smolcert_t* cert) {
  CborParser parser;
  CborValue it;
  CborError err = cbor_parser_init(buffer, size, 0, &parser, &it);
  sc_error_t sc_err;

  CborType type = cbor_value_get_type(&it);

  if (type != CborArrayType) {
    return Sc_Invalid_Format;
  }
  size_t arr_length = 0;
  cbor_value_get_array_length(&it, &arr_length);
  if (arr_length != 7) {
    return Sc_Invalid_Format;
  }

  assert(cbor_value_is_container(&it));
  CborValue array_it;
  err = cbor_value_enter_container(&it, &array_it);
  if (err) {
    return Sc_Invalid_Format;
  }

  if ( (sc_err = expect_uint64_t(&array_it, &cert->serial_number)) != Sc_No_Error) {
    return sc_err;
  }

  if ( (sc_err = expect_string(&array_it, &cert->issuer, &cert->issuer_len)) != Sc_No_Error) {
    return sc_err;
  }

  if ( (sc_err = parse_validity(&array_it, &cert->validity)) != Sc_No_Error) {
    return sc_err;
  }

  if ( (sc_err = expect_string(&array_it, &cert->subject, &cert->subject_len)) != Sc_No_Error) {
    return sc_err;
  }
  if ((sc_err = expect_fixed_length_bytes(&array_it, (uint8_t *)&cert->public_key, 32)) != Sc_No_Error) {
    return sc_err;
  }

  if ((sc_err = parse_extensions(&array_it, &cert->extensions, &cert->extensions_len)) != Sc_No_Error) {
    return sc_err;
  }

  if ((sc_err = expect_fixed_length_bytes(&array_it, (uint8_t *)&cert->signature, 64)) != Sc_No_Error) {
    return sc_err;
  }

  if (!cbor_value_at_end(&array_it)) {
    // Somethign strange happenend, the array was probably misformatted and declared an invalid
    // amount of items.
    return Sc_Invalid_Format;
  }

  if ((err = cbor_value_leave_container(&it, &array_it)) != CborNoError) {
    return Sc_Invalid_Format;
  }

  return Sc_No_Error;
}

sc_error_t parse_extensions(CborValue *it, sc_extension_t** extensions, size_t* extensions_len) {
  if (!cbor_value_is_array(it)) {
    return Sc_Invalid_Format;
  }

  size_t arr_len = 0;
  CborError err = cbor_value_get_array_length(it, &arr_len);
  if (arr_len == 0) {
    *extensions_len = 0;
    if ((err = cbor_value_advance(it)) != CborNoError){
      return Sc_Invalid_Format;
    } 
    return Sc_No_Error;
  }

  CborValue arr_it;
  if ((err = cbor_value_enter_container(it, &arr_it)) != CborNoError) {
    return Sc_Invalid_Format;
  }

  extensions = (sc_extension_t**)malloc(sizeof(sc_extension_t)*arr_len);
  sc_error_t sc_err;
  for (size_t i = 0; i<arr_len; i++) {
    if ((sc_err = parse_extension(&arr_it, extensions[i])) != Sc_No_Error) {
      free(extensions);
      return sc_err;
    }
  }
  if ((err = cbor_value_leave_container(it, &arr_it)) != CborNoError) {
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}

sc_error_t parse_extension(CborValue *it, sc_extension_t* extension) {
  if (cbor_value_get_type(it) != CborArrayType) {
    return Sc_Invalid_Format;
  }

  size_t arr_len = 0;
  cbor_value_get_array_length(it, &arr_len);
  if (arr_len != 3) {
    return Sc_Invalid_Format;
  }
  CborValue arr_it;
  CborError err = cbor_value_enter_container(it, &arr_it);
  if (err != CborNoError) {
    return Sc_Invalid_Format;
  }

  extension = (sc_extension_t*)malloc(sizeof(sc_extension_t));

  sc_error_t sc_err;
  if ((sc_err = expect_uint64_t(&arr_it, &extension->oid)) != Sc_No_Error) {
    free(extension);
    return sc_err;
  }

  if ((sc_err = expect_boolean(&arr_it, &extension->critical)) != Sc_No_Error) {
    free(extension);
    return sc_err;
  }

  if ((sc_err = expect_byte_string(&arr_it, &extension->value, &extension->value_len)) != Sc_No_Error) {
    free(extension);
    return sc_err;
  }
  if ((err = cbor_value_leave_container(it, &arr_it)) != CborNoError) {
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}

sc_error_t parse_validity(CborValue* it, sc_validity_t* validity) {
  if (cbor_value_get_type(it) != CborArrayType) {
    return Sc_Invalid_Format;
  }

  size_t arr_len = 0;
  cbor_value_get_array_length(it, &arr_len);
  if (arr_len != 2) {
    return Sc_Invalid_Format;
  }

  CborValue arr_it;
  CborError  err = cbor_value_enter_container(it, &arr_it);
  if (err != CborNoError) {
    return Sc_Invalid_Format;
  }

  sc_error_t sc_err;
  if ((sc_err = expect_uint64_t(&arr_it, &validity->not_before)) != Sc_No_Error) {
    return sc_err;
  }

  if ((sc_err = expect_uint64_t(&arr_it, &validity->not_after)) != Sc_No_Error) {
    return sc_err;
  }

  if ((err = cbor_value_leave_container(it, &arr_it)) != CborNoError) {
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}

sc_error_t expect_uint64_t(CborValue* it, uint64_t* val) {
  if (cbor_value_get_type(it) != CborIntegerType) {
    return Sc_Invalid_Format;
  }
  CborError err = cbor_value_get_uint64(it, val);
  if (err != CborNoError) {
    return Sc_Invalid_Format;
  }
  err = cbor_value_advance_fixed(it);
  if (err != CborNoError) {
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}

sc_error_t expect_boolean(CborValue* it, bool* val) {
  if (!cbor_value_is_boolean(it)) {
    return Sc_Invalid_Format;
  }

  CborError err = cbor_value_get_boolean(it, val);
  if (err != CborNoError) {
    return Sc_Invalid_Format;
  }

  if ((err = cbor_value_advance_fixed(it)) != CborNoError) {
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}

sc_error_t expect_string(CborValue* it, char** buf, size_t* buf_len) {
  if (cbor_value_get_type(it) != CborTextStringType) {
    return Sc_Invalid_Format;
  }

  CborError err = cbor_value_dup_text_string(it, buf, buf_len, it);
  if (err != CborNoError) {
    if(buf){
      free(buf);
    }
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}

sc_error_t expect_fixed_length_bytes(CborValue* it, uint8_t* buf, size_t exp_buf_len) {
  if (!cbor_value_is_byte_string(it)) {
    return Sc_Invalid_Format;
  }
  size_t buf_len = exp_buf_len;
  CborError err = cbor_value_copy_byte_string(it, buf, &buf_len, it);
  if (err != CborNoError) {
    return Sc_Invalid_Format;
  }
  if (buf_len != exp_buf_len) {
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}

sc_error_t expect_byte_string(CborValue *it, uint8_t** buf, size_t* buf_len) {
  if (!cbor_value_is_byte_string(it)) {
    return Sc_Invalid_Format;
  }

  CborError err = cbor_value_dup_byte_string(it, buf, buf_len, it);
  if (err != CborNoError) {
    if (buf) {
      free(buf);
    }
    return Sc_Invalid_Format;
  }
  return Sc_No_Error;
}