class ZCL_NTLM_ARC4 definition
  public
  final
  create public .

public section.

*"* public components of class ZCL_NTLM_ARC4
*"* do not include other source files here!!!
  class-methods DECRYPT
    importing
      !IV_KEY type STRING
      !IV_CIPHERTEXT type XSTRING
    returning
      value(RV_PLAINTEXT) type STRING
    raising
      CX_STATIC_CHECK .
  class-methods DECRYPT_HEX
    importing
      !IV_KEY type XSTRING
      !IV_CIPHERTEXT type XSTRING
    returning
      value(RV_PLAINTEXT) type XSTRING
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
  class-methods ENCRYPT_HEX
    importing
      !IV_KEY type XSTRING
      !IV_PLAINTEXT type XSTRING
    returning
      value(RV_CIPHERTEXT) type XSTRING
    raising
      CX_STATIC_CHECK .
  PROTECTED SECTION.
*"* protected components of class ZCL_NTLM_ARC4
*"* do not include other source files here!!!

    TYPES:
      ty_s TYPE x LENGTH 256 .

    CLASS-METHODS keystream
      IMPORTING
        !iv_key             TYPE xstring
        !iv_length          TYPE i
      RETURNING
        VALUE(rv_keystream) TYPE xstring
      RAISING
        cx_static_check .
    CLASS-METHODS ksa
      IMPORTING
        !iv_xkey    TYPE xstring
      RETURNING
        VALUE(rv_s) TYPE ty_s .
    CLASS-METHODS prga
      IMPORTING
        !iv_s       TYPE ty_s
        !iv_length  TYPE i
      RETURNING
        VALUE(rv_k) TYPE xstring .
    CLASS-METHODS to_string
      IMPORTING
        !iv_xstring      TYPE xstring
      RETURNING
        VALUE(rv_string) TYPE string
      RAISING
        cx_static_check .
    CLASS-METHODS to_xstring
      IMPORTING
        !iv_string        TYPE string
      RETURNING
        VALUE(rv_xstring) TYPE xstring
      RAISING
        cx_static_check .
    CLASS-METHODS xor
      IMPORTING
        !iv_val1      TYPE xstring
        !iv_val2      TYPE xstring
      RETURNING
        VALUE(rv_res) TYPE xstring .
  PRIVATE SECTION.
*"* private components of class ZCL_NTLM_ARC4
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_NTLM_ARC4 IMPLEMENTATION.


  METHOD DECRYPT.

    DATA: lv_xstr TYPE xstring.


    lv_xstr = decrypt_hex(
                iv_key        = to_xstring( iv_key )
                iv_ciphertext = iv_ciphertext ).

    rv_plaintext = to_string( lv_xstr ).

  ENDMETHOD.


  METHOD DECRYPT_HEX.

    rv_plaintext = encrypt_hex(
                     iv_key       = iv_key
                     iv_plaintext = iv_ciphertext ).

  ENDMETHOD.


  METHOD ENCRYPT.

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

    rv_ciphertext = encrypt_hex(
                      iv_key       = to_xstring( iv_key )
                      iv_plaintext = to_xstring( iv_plaintext ) ).

  ENDMETHOD.


  METHOD ENCRYPT_HEX.

    DATA: lv_k TYPE xstring.


    lv_k = keystream(
        iv_key    = iv_key
        iv_length = xstrlen( iv_plaintext ) ).

    rv_ciphertext = xor(
        iv_val1 = lv_k
        iv_val2 = iv_plaintext ).

  ENDMETHOD.


  METHOD KEYSTREAM.

    DATA: lv_s TYPE ty_s.


    lv_s = ksa( iv_key ).

    rv_keystream = prga( iv_s      = lv_s
                         iv_length = iv_length ).

  ENDMETHOD.


  METHOD KSA.

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


  METHOD PRGA.

    DATA: lv_x      TYPE x,
          lv_j      TYPE i,
          lv_i      TYPE i,
          lv_s      LIKE iv_s,
          lv_offset TYPE i.


    lv_s = iv_s.

    DO iv_length TIMES.
      lv_i = ( lv_i + 1 ) MOD 256.
      lv_j = ( lv_j + lv_s+lv_i(1) ) MOD 256.

      lv_x = lv_s+lv_i(1).
      lv_s+lv_i(1) = lv_s+lv_j(1).
      lv_s+lv_j(1) = lv_x.

      lv_offset = ( lv_s+lv_i(1) + lv_s+lv_j(1) ) MOD 256.
      lv_x = lv_s+lv_offset(1).

      CONCATENATE rv_k lv_x INTO rv_k IN BYTE MODE.
    ENDDO.

  ENDMETHOD.


  METHOD TO_STRING.

    DATA: lv_len TYPE i,
          lo_obj TYPE REF TO cl_abap_conv_in_ce.


    lo_obj = cl_abap_conv_in_ce=>create(
        input    = iv_xstring
        encoding = 'UTF-8' ).
    lv_len = xstrlen( iv_xstring ).

    lo_obj->read( EXPORTING n    = lv_len
                  IMPORTING data = rv_string ).

  ENDMETHOD.


  METHOD TO_XSTRING.

    DATA: lo_obj TYPE REF TO cl_abap_conv_out_ce.


    lo_obj = cl_abap_conv_out_ce=>create( encoding = 'UTF-8' ).

    lo_obj->convert( EXPORTING data = iv_string
                     IMPORTING buffer = rv_xstring ).

  ENDMETHOD.


  METHOD XOR.

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
