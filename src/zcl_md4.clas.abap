CLASS zcl_md4 DEFINITION
  PUBLIC
  CREATE PUBLIC .

  PUBLIC SECTION.

    TYPES:
*"* public components of class ZCL_MD4
*"* do not include other source files here!!!
      ty_byte4 TYPE x LENGTH 4 .
    TYPES:
      ty_byte16 TYPE x LENGTH 16 .

    CLASS-METHODS hash
      IMPORTING
        !iv_string     TYPE clike
        !iv_encoding   TYPE abap_encoding DEFAULT 'UTF-8'
      RETURNING
        VALUE(rv_hash) TYPE ty_byte16 .
    CLASS-METHODS hash_hex
      IMPORTING
        !iv_xstr       TYPE xstring
      RETURNING
        VALUE(rv_hash) TYPE ty_byte16 .
  PROTECTED SECTION.

    CLASS-METHODS codepage
      IMPORTING
        !iv_encoding      TYPE abap_encoding DEFAULT 'UTF-8'
        !iv_string        TYPE clike
      RETURNING
        VALUE(rv_xstring) TYPE xstring .
  PRIVATE SECTION.
*"* private components of class ZCL_MD4
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_MD4 IMPLEMENTATION.


  METHOD codepage.

    DATA: lo_obj TYPE REF TO cl_abap_conv_out_ce.


    lo_obj = cl_abap_conv_out_ce=>create( encoding = iv_encoding ).

    lo_obj->convert( EXPORTING
                       data = iv_string
                       n = strlen( iv_string )
                     IMPORTING buffer = rv_xstring ).

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


    lv_xstr = codepage( iv_encoding = iv_encoding
                        iv_string   = iv_string ).

    rv_hash = hash_hex( lv_xstr ).

  ENDMETHOD.


  METHOD hash_hex.

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

    DATA: lo_barrel TYPE REF TO lcl_barrel,
          lo_buffer TYPE REF TO lcl_buffer,
          lo_ff     TYPE REF TO lcl_ff,
          lo_gg     TYPE REF TO lcl_gg,
          lo_hh     TYPE REF TO lcl_hh.

    lo_buffer = NEW #( iv_xstr ).
    lo_barrel = NEW #( ).
    lo_ff = NEW #( io_barrel = lo_barrel io_buffer = lo_buffer ).
    lo_gg = NEW #( io_barrel = lo_barrel io_buffer = lo_buffer ).
    lo_hh = NEW #( io_barrel = lo_barrel io_buffer = lo_buffer ).

* 16 words = 64 byte
    DO lo_buffer->get_blocks( ) TIMES.
      lo_buffer->set_block( sy-index ).
      lo_barrel->snapshot( ).

      lo_ff->hash( ).
      lo_gg->hash( ).
      lo_hh->hash( ).

      lo_barrel->accumulate( ).
    ENDDO.

    rv_hash = lo_barrel->get_hash( ).

  ENDMETHOD.
ENDCLASS.
