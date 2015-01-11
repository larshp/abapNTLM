class ZCL_ARC4 definition
  public
  final
  create public .

public section.
*"* public components of class ZCL_ARC4
*"* do not include other source files here!!!

  class-methods DECRYPT
    importing
      !IV_KEY type STRING
      !IV_CIPHERTEXT type XSTRING
    returning
      value(RV_PLAINTEXT) type STRING
    raising
      CX_STATIC_CHECK .
  class-methods ENCRYPT
    importing
      !IV_KEY type STRING
      !IV_PLAINTEXT type STRING
    returning
      value(RV_CIPHERTEXT) type XSTRING
    raising
      CX_STATIC_CHECK .
protected section.
*"* protected components of class ZCL_ARC4
*"* do not include other source files here!!!

  types:
    ty_s TYPE x LENGTH 256 .

  class-methods KEYSTREAM
    importing
      !IV_KEY type STRING
      !IV_LENGTH type I
    returning
      value(RV_KEYSTREAM) type XSTRING
    raising
      CX_STATIC_CHECK .
  class-methods KSA
    importing
      !IV_XKEY type XSTRING
    returning
      value(RV_S) type TY_S .
  class-methods PRGA
    importing
      value(IV_S) type TY_S
      !IV_LENGTH type I
    returning
      value(RV_K) type XSTRING .
  class-methods TO_STRING
    importing
      !IV_XSTRING type XSTRING
    returning
      value(RV_STRING) type STRING
    raising
      CX_STATIC_CHECK .
  class-methods TO_XSTRING
    importing
      !IV_STRING type STRING
    returning
      value(RV_XSTRING) type XSTRING
    raising
      CX_STATIC_CHECK .
  class-methods XOR
    importing
      !IV_VAL1 type XSTRING
      !IV_VAL2 type XSTRING
    returning
      value(RV_RES) type XSTRING .
private section.
*"* private components of class ZCL_ARC4
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_ARC4 IMPLEMENTATION.


METHOD decrypt.

  DATA: lv_xstr TYPE xstring,
        lv_k    TYPE xstring.


  lv_k = keystream(
      iv_key    = iv_key
      iv_length = xstrlen( iv_ciphertext ) ).

  lv_xstr = xor(
      iv_val1 = lv_k
      iv_val2 = iv_ciphertext ).

  rv_plaintext = to_string( lv_xstr ).

ENDMETHOD.


METHOD encrypt.

* The MIT License (MIT)
*
* Copyright (c) 2015 Lars Hvam
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.

  DATA: lv_k TYPE xstring.


  lv_k = keystream(
      iv_key    = iv_key
      iv_length = strlen( iv_plaintext ) ).

  rv_ciphertext = xor(
      iv_val1 = lv_k
      iv_val2 = to_xstring( iv_plaintext ) ).

ENDMETHOD.


METHOD keystream.

  DATA: lv_s TYPE ty_s.


  lv_s = ksa( to_xstring( iv_key ) ).

  rv_keystream = prga( iv_s      = lv_s
                       iv_length = iv_length ).

ENDMETHOD.


METHOD ksa.

  DATA: lv_offset TYPE i,
        lv_j      TYPE i,
        lv_i      TYPE i,
        lv_x      TYPE x.


  DO 256 TIMES.
    lv_offset = sy-index - 1.
    rv_s+lv_offset(1) = lv_offset.
  ENDDO.

  WHILE lv_i < 256.
    lv_offset = lv_i MOD xstrlen( iv_xkey ).

    lv_j = ( lv_j + rv_s+lv_i(1) + iv_xkey+lv_offset(1) ) MOD 256.

    lv_x = rv_s+lv_i(1).
    rv_s+lv_i(1) = rv_s+lv_j(1).
    rv_s+lv_j(1) = lv_x.

    lv_i = lv_i + 1.
  ENDWHILE.

ENDMETHOD.


METHOD prga.

  DATA: lv_x      TYPE x,
        lv_j      TYPE i,
        lv_i      TYPE i,
        lv_offset TYPE i.


  DO iv_length TIMES.
    lv_i = ( lv_i + 1 ) MOD 256.
    lv_j = ( lv_j + iv_s+lv_i(1) ) MOD 256.

    lv_x = iv_s+lv_i(1).
    iv_s+lv_i(1) = iv_s+lv_j(1).
    iv_s+lv_j(1) = lv_x.

    lv_offset = ( iv_s+lv_i(1) + iv_s+lv_j(1) ) MOD 256.
    lv_x = iv_s+lv_offset(1).

    CONCATENATE rv_k lv_x INTO rv_k IN BYTE MODE.
  ENDDO.

ENDMETHOD.


METHOD to_string.

  DATA: lv_len TYPE i,
        lo_obj TYPE REF TO cl_abap_conv_in_ce.


  lo_obj = cl_abap_conv_in_ce=>create(
      input    = iv_xstring
      encoding = 'UTF-8' ).
  lv_len = xstrlen( iv_xstring ).

  lo_obj->read( EXPORTING n    = lv_len
                IMPORTING data = rv_string ).

ENDMETHOD.


METHOD to_xstring.

  DATA: lo_obj TYPE REF TO cl_abap_conv_out_ce.


  lo_obj = cl_abap_conv_out_ce=>create( encoding = 'UTF-8' ).

  lo_obj->convert( EXPORTING data = iv_string
                   IMPORTING buffer = rv_xstring ).

ENDMETHOD.


METHOD xor.

  DATA: lv_x      TYPE x,
        lv_offset TYPE i.


  ASSERT xstrlen( iv_val1 ) = xstrlen( iv_val2 ).

  DO xstrlen( iv_val1 ) TIMES.
    lv_offset = sy-index - 1.

    lv_x = iv_val1+lv_offset(1) BIT-XOR iv_val2+lv_offset(1).

    CONCATENATE rv_res lv_x INTO rv_res IN BYTE MODE.
  ENDDO.

ENDMETHOD.
ENDCLASS.