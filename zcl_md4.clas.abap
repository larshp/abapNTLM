class ZCL_MD4 definition
  public
  final
  create public .

public section.
*"* public components of class ZCL_MD4
*"* do not include other source files here!!!

  types:
    TY_BYTE4 type x length 4 .
  types:
    TY_BYTE16 type x length 16 .

  class ZCL_MD4 definition load .
  class-methods HASH
    importing
      !IV_STRING type STRING
    returning
      value(RV_HASH) type ZCL_MD4=>TY_BYTE16 .
protected section.
*"* protected components of class ZCL_MD4
*"* do not include other source files here!!!

  class-methods SHIFT
    importing
      !IV_INPUT type TY_BYTE4
      !IV_PLACES type I
    returning
      value(RV_OUTPUT) type TY_BYTE4 .
  class-methods FUNC_F
    importing
      !IV_X type TY_BYTE4
      !IV_Y type TY_BYTE4
      !IV_Z type TY_BYTE4
    returning
      value(RV_RES) type TY_BYTE4 .
  class-methods FUNC_FF
    importing
      !IV_A type TY_BYTE4
      !IV_B type TY_BYTE4
      !IV_C type TY_BYTE4
      !IV_D type TY_BYTE4
      !IV_X type I
      !IV_S type I
    returning
      value(RV_RES) type TY_BYTE4 .
  class-methods FUNC_GG
    importing
      !IV_A type TY_BYTE4
      !IV_B type TY_BYTE4
      !IV_C type TY_BYTE4
      !IV_D type TY_BYTE4
      !IV_X type I
      !IV_S type I
    returning
      value(RV_RES) type TY_BYTE4 .
  class-methods FUNC_HH
    importing
      !IV_A type TY_BYTE4
      !IV_B type TY_BYTE4
      !IV_C type TY_BYTE4
      !IV_D type TY_BYTE4
      !IV_X type I
      !IV_S type I
    returning
      value(RV_RES) type TY_BYTE4 .
  class-methods FUNC_G
    importing
      !IV_X type TY_BYTE4
      !IV_Y type TY_BYTE4
      !IV_Z type TY_BYTE4
    returning
      value(RV_RES) type TY_BYTE4 .
  class-methods FUNC_H
    importing
      !IV_X type TY_BYTE4
      !IV_Y type TY_BYTE4
      !IV_Z type TY_BYTE4
    returning
      value(RV_RES) type TY_BYTE4 .
  class-methods PADDING_LENGTH
    importing
      !IV_INPUT type XSTRING
    returning
      value(RV_XSTRING) type XSTRING .
  class-methods TO_UTF8
    importing
      !IV_STRING type STRING
    returning
      value(RV_XSTRING) type XSTRING .
private section.
*"* private components of class ZCL_MD4
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_MD4 IMPLEMENTATION.


METHOD func_f.

* XY v not(X) Z

  rv_res = ( iv_x BIT-AND iv_y ) BIT-OR ( ( BIT-NOT iv_x ) BIT-AND iv_z ).

ENDMETHOD.


METHOD func_ff.

  DATA: lv_f TYPE f.

* (a + F(b,c,d) + X[k]) <<< s

  lv_f = iv_a +
    func_f( iv_x = iv_b
            iv_y = iv_c
            iv_z = iv_d ) +
    iv_x.
  lv_f = lv_f MOD ( ( 2 ** 31 ) - 1 ).
  rv_res = lv_f.
  rv_res = shift( iv_input  = rv_res
                  iv_places = iv_s ).

ENDMETHOD.


METHOD func_g.

* XY v XZ v YZ

  rv_res = ( iv_x BIT-AND iv_y )
    BIT-OR ( iv_x BIT-AND iv_z )
    BIT-OR ( iv_y BIT-AND iv_z ).

ENDMETHOD.


METHOD func_gg.

  CONSTANTS: lc_add TYPE x LENGTH 4 VALUE '5A827999'.

  DATA: lv_f TYPE f.

* (a + G(b,c,d) + X[k] + 5A827999) <<< s

  lv_f = iv_a +
    func_g( iv_x = iv_b
            iv_y = iv_c
            iv_z = iv_d ) +
    iv_x + lc_add.
  lv_f = lv_f MOD ( ( 2 ** 31 ) - 1 ).
  rv_res = lv_f.
  rv_res = shift( iv_input  = rv_res
                  iv_places = iv_s ).

ENDMETHOD.


METHOD func_h.

* X xor Y xor Z

  rv_res = ( iv_x BIT-XOR iv_y ) BIT-XOR iv_z.

ENDMETHOD.


METHOD func_hh.

  CONSTANTS: lc_add TYPE x LENGTH 4 VALUE '6ED9EBA1'.

  DATA: lv_f TYPE f.

* (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s

  lv_f = iv_a +
    func_g( iv_x = iv_b
            iv_y = iv_c
            iv_z = iv_d ) +
    iv_x + lc_add.
  lv_f = lv_f MOD ( ( 2 ** 31 ) - 1 ).
  rv_res = lv_f.
  rv_res = shift( iv_input  = rv_res
                  iv_places = iv_s ).

ENDMETHOD.


METHOD hash.

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

* http://tools.ietf.org/html/rfc1320

  DATA: lv_xstr TYPE xstring.

  DATA: lv_a TYPE x LENGTH 4 VALUE '01234567',
        lv_b TYPE x LENGTH 4 VALUE '89ABCDEF',
        lv_c TYPE x LENGTH 4 VALUE 'FEDCBA98',
        lv_d TYPE x LENGTH 4 VALUE '76543210'.

  DATA: lv_aa TYPE x LENGTH 4,
        lv_bb TYPE x LENGTH 4,
        lv_cc TYPE x LENGTH 4,
        lv_dd TYPE x LENGTH 4.

  DATA: lv_x TYPE x LENGTH 2,
        lv_offset TYPE i,
        lv_bit TYPE i.

  DEFINE _ff.
    get bit &5 + 1 of lv_x into lv_bit.
    assert sy-subrc = 0.
    lv_a = func_ff(
      iv_a   = &1
      iv_b   = &2
      iv_c   = &3
      iv_d   = &4
      iv_x   = lv_bit
      iv_s   = &6 ).
  END-OF-DEFINITION.

  DEFINE _gg.
    get bit &5 + 1 of lv_x into lv_bit.
    assert sy-subrc = 0.
    lv_a = func_gg(
      iv_a   = &1
      iv_b   = &2
      iv_c   = &3
      iv_d   = &4
      iv_x   = lv_bit
      iv_s   = &6 ).
  END-OF-DEFINITION.

  DEFINE _hh.
    get bit &5 + 1 of lv_x into lv_bit.
    assert sy-subrc = 0.
    lv_a = func_hh(
      iv_a   = &1
      iv_b   = &2
      iv_c   = &3
      iv_d   = &4
      iv_x   = lv_bit
      iv_s   = &6 ).
  END-OF-DEFINITION.


  lv_xstr = to_utf8( iv_string ).
  lv_xstr = padding_length( lv_xstr ).

  DO xstrlen( lv_xstr ) / 2 TIMES.
    lv_offset = ( sy-index - 1 ) * 2.

    lv_aa = lv_a.
    lv_bb = lv_b.
    lv_cc = lv_c.
    lv_dd = lv_d.

    lv_x = lv_xstr+lv_offset(2).

* round 1
    _ff lv_a lv_b lv_c lv_d  0  3.
    _ff lv_d lv_a lv_b lv_c  1  7.
    _ff lv_c lv_d lv_a lv_b  2 11.
    _ff lv_b lv_c lv_d lv_a  3 19.
    _ff lv_a lv_b lv_c lv_d  4  3.
    _ff lv_d lv_a lv_b lv_c  5  7.
    _ff lv_c lv_d lv_a lv_b  6 11.
    _ff lv_b lv_c lv_d lv_a  7 19.
    _ff lv_a lv_b lv_c lv_d  8  3.
    _ff lv_d lv_a lv_b lv_c  9  7.
    _ff lv_c lv_d lv_a lv_b 10 11.
    _ff lv_b lv_c lv_d lv_a 11 19.
    _ff lv_a lv_b lv_c lv_d 12  3.
    _ff lv_d lv_a lv_b lv_c 13  7.
    _ff lv_c lv_d lv_a lv_b 14 11.
    _ff lv_b lv_c lv_d lv_a 15 19.

* round 2
    _gg lv_a lv_b lv_c lv_d  0  3.
    _gg lv_d lv_a lv_b lv_c  4  5.
    _gg lv_c lv_d lv_a lv_b  8  9.
    _gg lv_b lv_c lv_d lv_a 12 13.
    _gg lv_a lv_b lv_c lv_d  1  3.
    _gg lv_d lv_a lv_b lv_c  5  5.
    _gg lv_c lv_d lv_a lv_b  9  9.
    _gg lv_b lv_c lv_d lv_a 13 13.
    _gg lv_a lv_b lv_c lv_d  2  3.
    _gg lv_d lv_a lv_b lv_c  6  5.
    _gg lv_c lv_d lv_a lv_b 10  9.
    _gg lv_b lv_c lv_d lv_a 14 13.
    _gg lv_a lv_b lv_c lv_d  3  3.
    _gg lv_d lv_a lv_b lv_c  7  5.
    _gg lv_c lv_d lv_a lv_b 11  9.
    _gg lv_b lv_c lv_d lv_a 15 13.

* round 3
    _hh lv_a lv_b lv_c lv_d  0  3.
    _hh lv_d lv_a lv_b lv_c  8  9.
    _hh lv_c lv_d lv_a lv_b  4 11.
    _hh lv_b lv_c lv_d lv_a 12 15.
    _hh lv_a lv_b lv_c lv_d  2  3.
    _hh lv_d lv_a lv_b lv_c 10  9.
    _hh lv_c lv_d lv_a lv_b  6 11.
    _hh lv_b lv_c lv_d lv_a 14 15.
    _hh lv_a lv_b lv_c lv_d  1  3.
    _hh lv_d lv_a lv_b lv_c  9  9.
    _hh lv_c lv_d lv_a lv_b  5 11.
    _hh lv_b lv_c lv_d lv_a 13 15.
    _hh lv_a lv_b lv_c lv_d  3  3.
    _hh lv_d lv_a lv_b lv_c 11  9.
    _hh lv_c lv_d lv_a lv_b  7 11.
    _hh lv_b lv_c lv_d lv_a 15 15.

    lv_a = ( lv_a + lv_aa ) MOD ( 2 ** 31 - 1 ).
    lv_b = ( lv_b + lv_bb ) MOD ( 2 ** 31 - 1 ).
    lv_c = ( lv_c + lv_cc ) MOD ( 2 ** 31 - 1 ).
    lv_d = ( lv_d + lv_dd ) MOD ( 2 ** 31 - 1 ).

  ENDDO.

  CONCATENATE lv_a lv_b lv_c lv_d INTO rv_hash IN BYTE MODE.

ENDMETHOD.


METHOD padding_length.

  CONSTANTS: lc_x0 TYPE x LENGTH 1 VALUE '00',
             lc_x1 TYPE x LENGTH 1 VALUE '80'.

  DATA: lv_length TYPE x LENGTH 8.


  CONCATENATE iv_input lc_x1 INTO rv_xstring IN BYTE MODE.

  WHILE xstrlen( rv_xstring ) MOD 64 <> 56.
    CONCATENATE rv_xstring lc_x0 INTO rv_xstring IN BYTE MODE.
  ENDWHILE.

  lv_length = xstrlen( iv_input ) * 8.
  CONCATENATE rv_xstring lv_length INTO rv_xstring IN BYTE MODE.

ENDMETHOD.


METHOD shift.

  DATA: lv_bits   TYPE c LENGTH 32,
        lv_offset TYPE i,
        lv_bit    TYPE c LENGTH 1.


  DO 32 TIMES.
    GET BIT sy-index OF iv_input INTO lv_bit.
    CONCATENATE lv_bits lv_bit INTO lv_bits.
  ENDDO.

  SHIFT lv_bits LEFT CIRCULAR BY iv_places PLACES.

  DO 32 TIMES.
    lv_offset = sy-index - 1.
    lv_bit = lv_bits+lv_offset(1).
    SET BIT lv_offset + 1 OF rv_output TO lv_bit.
  ENDDO.

ENDMETHOD.


METHOD to_utf8.

  DATA: lo_obj TYPE REF TO cl_abap_conv_out_ce.


  lo_obj = cl_abap_conv_out_ce=>create( encoding = 'UTF-8' ).

  lo_obj->convert( EXPORTING data = iv_string
                   IMPORTING buffer = rv_xstring ).

ENDMETHOD.
ENDCLASS.