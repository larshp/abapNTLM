*"* use this source file for the definition and implementation of
*"* local helper classes, interface definitions and type
*"* declarations

TYPES:
  BEGIN OF ty_fields,
    len    TYPE i,
    maxlen TYPE i,
    offset TYPE i,
  END OF ty_fields .

CLASS lcl_convert DEFINITION DEFERRED.
CLASS zcl_ntlm DEFINITION LOCAL FRIENDS lcl_convert.

CLASS lcl_reader DEFINITION DEFERRED.
CLASS zcl_ntlm DEFINITION LOCAL FRIENDS lcl_reader.

CLASS lcl_writer DEFINITION DEFERRED.
CLASS zcl_ntlm DEFINITION LOCAL FRIENDS lcl_writer.

CLASS lcl_util DEFINITION DEFERRED.
CLASS zcl_ntlm DEFINITION LOCAL FRIENDS lcl_util.

*----------------------------------------------------------------------*
*       CLASS lcl_time DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_util DEFINITION FINAL.

  PUBLIC SECTION.
    CLASS-METHODS class_constructor.

    CLASS-METHODS since_epoc_hex
      RETURNING
                VALUE(rv_hex) TYPE zcl_ntlm=>ty_byte8
      RAISING   cx_static_check.

    CLASS-METHODS since_epoc
      IMPORTING iv_time       TYPE t DEFAULT sy-uzeit
                iv_date       TYPE d DEFAULT sy-datum
      RETURNING VALUE(rv_num) TYPE zntlm_dec_22.

    CLASS-METHODS hmac_md5
      IMPORTING
        iv_key         TYPE xsequence
        iv_data        TYPE xsequence
      RETURNING
        VALUE(rv_hash) TYPE xstring
      RAISING
        cx_static_check.

    CLASS-METHODS random_nonce
      RETURNING
        VALUE(rv_data) TYPE zcl_ntlm=>ty_byte8.

    CLASS-METHODS md5
      IMPORTING
        iv_data        TYPE xstring
      RETURNING
        VALUE(rv_hash) TYPE zcl_ntlm=>ty_byte16.

  PRIVATE SECTION.

    CLASS-DATA:
      mo_random TYPE REF TO cl_abap_random.

ENDCLASS.                    "lcl_time DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_convert DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_convert DEFINITION FINAL.

  PUBLIC SECTION.
    CLASS-METHODS to_64bit
      IMPORTING
        iv_num        TYPE zntlm_dec_22
      RETURNING
        VALUE(rv_hex) TYPE zcl_ntlm=>ty_byte8.
    CLASS-METHODS fields_decode
      IMPORTING
        iv_byte8         TYPE zcl_ntlm=>ty_byte8
      RETURNING
        VALUE(rs_fields) TYPE ty_fields.
    CLASS-METHODS fields_encode
      IMPORTING
        is_fields       TYPE ty_fields
      RETURNING
        VALUE(rv_byte8) TYPE zcl_ntlm=>ty_byte8.
    CLASS-METHODS base64_decode
      IMPORTING
        iv_string         TYPE string
      RETURNING
        VALUE(rv_xstring) TYPE xstring.
    CLASS-METHODS base64_encode
      IMPORTING
        iv_xstring       TYPE xstring
      RETURNING
        VALUE(rv_string) TYPE string.
    CLASS-METHODS flags_decode
      IMPORTING
        iv_hex          TYPE zcl_ntlm=>ty_byte4
      RETURNING
        VALUE(rs_flags) TYPE zcl_ntlm=>ty_flags.
    CLASS-METHODS flags_encode
      IMPORTING
        is_flags      TYPE zcl_ntlm=>ty_flags
      RETURNING
        VALUE(rv_hex) TYPE zcl_ntlm=>ty_byte4.
    CLASS-METHODS byte2_to_int
      IMPORTING
        iv_byte2      TYPE zcl_ntlm=>ty_byte2
      RETURNING
        VALUE(rv_int) TYPE i.
    CLASS-METHODS byte4_to_int
      IMPORTING
        iv_byte4      TYPE zcl_ntlm=>ty_byte4
      RETURNING
        VALUE(rv_int) TYPE i.
    CLASS-METHODS int_to_byte2
      IMPORTING
        iv_int          TYPE i
      RETURNING
        VALUE(rv_byte2) TYPE zcl_ntlm=>ty_byte2.
    CLASS-METHODS int_to_byte4
      IMPORTING
        iv_int          TYPE i
      RETURNING
        VALUE(rv_byte4) TYPE zcl_ntlm=>ty_byte4.
    CLASS-METHODS codepage_4103
      IMPORTING
        iv_string         TYPE clike
      RETURNING
        VALUE(rv_xstring) TYPE xstring.
    CLASS-METHODS codepage_utf_8
      IMPORTING
        iv_string         TYPE string
      RETURNING
        VALUE(rv_xstring) TYPE xstring.
    CLASS-METHODS codepage_4103_x
      IMPORTING
        iv_xstring       TYPE xstring
      RETURNING
        VALUE(rv_string) TYPE string.
    CLASS-METHODS codepage_utf_8_x
      IMPORTING
        iv_xstring       TYPE xstring
      RETURNING
        VALUE(rv_string) TYPE string.

ENDCLASS.                    "lcl_convert DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_time IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_util IMPLEMENTATION.

  METHOD class_constructor.

    mo_random = cl_abap_random=>create( cl_abap_random=>seed( ) ).

  ENDMETHOD.

  METHOD md5.

    DATA lv_empty TYPE xstring.
    DATA lv_hash TYPE xstring.

    TRY.
        cl_abap_hmac=>calculate_hmac_for_raw(
          EXPORTING
            if_algorithm   = 'MD5'
            if_key         = lv_empty
            if_data        = iv_data
          IMPORTING
            ef_hmacxstring = lv_hash ).
      CATCH cx_abap_message_digest.
        ASSERT 1 = 2.
    ENDTRY.

    rv_hash = lv_hash.

  ENDMETHOD.

  METHOD random_nonce.

    rv_data+4 = mo_random->int( ).
    rv_data(4) = mo_random->int( ).

  ENDMETHOD.

  METHOD hmac_md5.

    DATA lv_key  TYPE xstring.

    lv_key = iv_key. " convert type

    cl_abap_hmac=>calculate_hmac_for_raw(
      EXPORTING
        if_algorithm   = 'MD5'
        if_key         = lv_key
        if_data        = iv_data
      IMPORTING
        ef_hmacxstring = rv_hash ).

  ENDMETHOD.

  METHOD since_epoc.
* tenths of a microsecond since 1 jan 1601, encoded as little endian signed 64 bit value

    DATA: lv_secs   TYPE tzntstmpl,
          lv_tstmp1 TYPE p,
          lv_tstmp2 TYPE p.


    cl_abap_tstmp=>systemtstmp_syst2utc(
      EXPORTING
        syst_date = iv_date
        syst_time = iv_time
      IMPORTING
        utc_tstmp = lv_tstmp1 ).

    lv_tstmp2 = '16010101000000'.
    lv_secs = cl_abap_tstmp=>subtract(
        tstmp1 = lv_tstmp1
        tstmp2 = lv_tstmp2 ).
    rv_num = lv_secs * ( 10 ** 7 ).

  ENDMETHOD.

  METHOD since_epoc_hex.

    DATA lv_lsec TYPE zntlm_dec_22.


    lv_lsec = since_epoc( ).
    rv_hex = lcl_convert=>to_64bit( lv_lsec ).

  ENDMETHOD.

ENDCLASS.

*----------------------------------------------------------------------*
*       CLASS lcl_convert IMPLMENTATION.
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_convert IMPLEMENTATION.

  METHOD to_64bit.

    DATA: lv_c     TYPE c LENGTH 1,
          lv_xres  TYPE x LENGTH 8,
          lv_index TYPE i,
          lv_num   LIKE iv_num.


    lv_num = iv_num.

* hmm, this is crazy, since there are no 64 bit types in ABAP
* INT8 was introduced in 750
    DO 64 TIMES.
      lv_index = 64 - sy-index + 1.

      lv_c = lv_num MOD 2.
      lv_num = lv_num DIV 2.

      SET BIT lv_index OF lv_xres TO lv_c.
    ENDDO.

    CONCATENATE
      lv_xres+7(1) lv_xres+6(1) lv_xres+5(1) lv_xres+4(1)
      lv_xres+3(1) lv_xres+2(1) lv_xres+1(1) lv_xres(1)
      INTO rv_hex IN BYTE MODE.

  ENDMETHOD.                    "to_64bit

  METHOD codepage_4103_x.

    DATA: lo_obj TYPE REF TO cl_abap_conv_in_ce.


    lo_obj = cl_abap_conv_in_ce=>create( encoding = '4103' ).

    lo_obj->convert( EXPORTING input = iv_xstring
                     IMPORTING data = rv_string ).

  ENDMETHOD.                    "codepage_4103_x

  METHOD codepage_utf_8_x.

    DATA: lo_obj TYPE REF TO cl_abap_conv_in_ce.


    lo_obj = cl_abap_conv_in_ce=>create( encoding = 'UTF-8' ).

    lo_obj->convert( EXPORTING input = iv_xstring
                     IMPORTING data = rv_string ).

  ENDMETHOD.                    "codepage_utf_8_x

  METHOD codepage_utf_8.

    DATA: lo_obj TYPE REF TO cl_abap_conv_out_ce.


    lo_obj = cl_abap_conv_out_ce=>create( encoding = 'UTF-8' ).

    lo_obj->convert( EXPORTING data = iv_string
                     IMPORTING buffer = rv_xstring ).

  ENDMETHOD.                    "codepage_UTF_8

  METHOD codepage_4103.

    DATA: lo_obj TYPE REF TO cl_abap_conv_out_ce.


    lo_obj = cl_abap_conv_out_ce=>create( encoding = '4103' ).

    lo_obj->convert( EXPORTING data = iv_string
                     IMPORTING buffer = rv_xstring ).

  ENDMETHOD.                    "codepage_4103

  METHOD fields_decode.

    DATA: lv_byte2 TYPE zcl_ntlm=>ty_byte2,
          lv_byte4 TYPE zcl_ntlm=>ty_byte4.


    lv_byte2 = iv_byte8(2).
    rs_fields-len = byte2_to_int( lv_byte2 ).

    lv_byte2 = iv_byte8+2(2).
    rs_fields-maxlen = byte2_to_int( lv_byte2 ).

    lv_byte4 = iv_byte8+4(4).
    rs_fields-offset = byte4_to_int( lv_byte4 ).

  ENDMETHOD.                    "fields_decode

  METHOD fields_encode.

    rv_byte8(2) = int_to_byte2( is_fields-len ).
    rv_byte8+2(2) = int_to_byte2( is_fields-maxlen ).
    rv_byte8+4(4) = int_to_byte4( is_fields-offset ).

  ENDMETHOD.                    "fields_encode

  METHOD base64_decode.

    rv_xstring = cl_http_utility=>decode_x_base64( iv_string ).

  ENDMETHOD.

  METHOD base64_encode.

    rv_string = cl_http_utility=>encode_x_base64( iv_xstring ).

  ENDMETHOD.

  METHOD flags_decode.

    DATA: lv_c TYPE c LENGTH 1,
          lv_x TYPE x LENGTH 1.


    lv_x = iv_hex.
    GET BIT 8 OF lv_x INTO lv_c.
    rs_flags-negotiate_unicode = boolc( lv_c = '1' ).
    GET BIT 7 OF lv_x INTO lv_c.
    rs_flags-negotiate_oem = boolc( lv_c = '1' ).
    GET BIT 6 OF lv_x INTO lv_c.
    rs_flags-request_target = boolc( lv_c = '1' ).
    GET BIT 5 OF lv_x INTO lv_c.
    rs_flags-r10 = boolc( lv_c = '1' ).
    GET BIT 4 OF lv_x INTO lv_c.
    rs_flags-negotiate_sign = boolc( lv_c = '1' ).
    GET BIT 3 OF lv_x INTO lv_c.
    rs_flags-negotiate_seal = boolc( lv_c = '1' ).
    GET BIT 2 OF lv_x INTO lv_c.
    rs_flags-negotiate_datagram = boolc( lv_c = '1' ).
    GET BIT 1 OF lv_x INTO lv_c.
    rs_flags-negotiate_lm_key = boolc( lv_c = '1' ).

    lv_x = iv_hex+1.
    GET BIT 8 OF lv_x INTO lv_c.
    rs_flags-r9 = boolc( lv_c = '1' ).
    GET BIT 7 OF lv_x INTO lv_c.
    rs_flags-negotiate_ntlm = boolc( lv_c = '1' ).
    GET BIT 6 OF lv_x INTO lv_c.
    rs_flags-r8 = boolc( lv_c = '1' ).
    GET BIT 5 OF lv_x INTO lv_c.
    rs_flags-anonymous = boolc( lv_c = '1' ).
    GET BIT 4 OF lv_x INTO lv_c.
    rs_flags-negotiate_oem_domain_supplied = boolc( lv_c = '1' ).
    GET BIT 3 OF lv_x INTO lv_c.
    rs_flags-negotiate_oem_workstation_sup = boolc( lv_c = '1' ).
    GET BIT 2 OF lv_x INTO lv_c.
    rs_flags-r7 = boolc( lv_c = '1' ).
    GET BIT 1 OF lv_x INTO lv_c.
    rs_flags-negotiate_always_sign = boolc( lv_c = '1' ).

    lv_x = iv_hex+2.
    GET BIT 8 OF lv_x INTO lv_c.
    rs_flags-target_type_domain = boolc( lv_c = '1' ).
    GET BIT 7 OF lv_x INTO lv_c.
    rs_flags-target_type_server = boolc( lv_c = '1' ).
    GET BIT 6 OF lv_x INTO lv_c.
    rs_flags-r6 = boolc( lv_c = '1' ).
    GET BIT 5 OF lv_x INTO lv_c.
    rs_flags-negotiate_extended_session_sec = boolc( lv_c = '1' ).
    GET BIT 4 OF lv_x INTO lv_c.
    rs_flags-negotiate_identity = boolc( lv_c = '1' ).
    GET BIT 3 OF lv_x INTO lv_c.
    rs_flags-r5 = boolc( lv_c = '1' ).
    GET BIT 2 OF lv_x INTO lv_c.
    rs_flags-request_non_nt_session_key = boolc( lv_c = '1' ).
    GET BIT 1 OF lv_x INTO lv_c.
    rs_flags-negotiate_target_info = boolc( lv_c = '1' ).

    lv_x = iv_hex+3.
    GET BIT 1 OF lv_x INTO lv_c.
    rs_flags-r4 = boolc( lv_c = '1' ).
    GET BIT 2 OF lv_x INTO lv_c.
    rs_flags-negotiate_version = boolc( lv_c = '1' ).
    GET BIT 3 OF lv_x INTO lv_c.
    rs_flags-r3 = boolc( lv_c = '1' ).
    GET BIT 4 OF lv_x INTO lv_c.
    rs_flags-r2 = boolc( lv_c = '1' ).
    GET BIT 5 OF lv_x INTO lv_c.
    rs_flags-r1 = boolc( lv_c = '1' ).
    GET BIT 6 OF lv_x INTO lv_c.
    rs_flags-negotiate_128 = boolc( lv_c = '1' ).
    GET BIT 7 OF lv_x INTO lv_c.
    rs_flags-negotiate_key_exch = boolc( lv_c = '1' ).
    GET BIT 8 OF lv_x INTO lv_c.
    rs_flags-negotiate_56 = boolc( lv_c = '1' ).

  ENDMETHOD.                    "flags_decode

  METHOD flags_encode.

    DATA lv_x TYPE x LENGTH 1.


    CLEAR lv_x.
    IF is_flags-negotiate_unicode = abap_true.
      SET BIT 8 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_oem = abap_true.
      SET BIT 7 OF lv_x.
    ENDIF.
    IF is_flags-request_target = abap_true.
      SET BIT 6 OF lv_x.
    ENDIF.
    IF is_flags-r10 = abap_true.
      SET BIT 5 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_sign = abap_true.
      SET BIT 4 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_seal = abap_true.
      SET BIT 3 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_datagram = abap_true.
      SET BIT 2 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_lm_key = abap_true.
      SET BIT 1 OF lv_x.
    ENDIF.
    rv_hex(1) = lv_x.

    CLEAR lv_x.
    IF is_flags-r9 = abap_true.
      SET BIT 8 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_ntlm = abap_true.
      SET BIT 7 OF lv_x.
    ENDIF.
    IF is_flags-r8 = abap_true.
      SET BIT 6 OF lv_x.
    ENDIF.
    IF is_flags-anonymous = abap_true.
      SET BIT 5 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_oem_domain_supplied = abap_true.
      SET BIT 4 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_oem_workstation_sup = abap_true.
      SET BIT 3 OF lv_x.
    ENDIF.
    IF is_flags-r7 = abap_true.
      SET BIT 2 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_always_sign = abap_true.
      SET BIT 1 OF lv_x.
    ENDIF.
    rv_hex+1(1) = lv_x.

    CLEAR lv_x.
    IF is_flags-target_type_domain = abap_true.
      SET BIT 8 OF lv_x.
    ENDIF.
    IF is_flags-target_type_server = abap_true.
      SET BIT 7 OF lv_x.
    ENDIF.
    IF is_flags-r6 = abap_true.
      SET BIT 6 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_extended_session_sec = abap_true.
      SET BIT 5 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_identity = abap_true.
      SET BIT 4 OF lv_x.
    ENDIF.
    IF is_flags-r5 = abap_true.
      SET BIT 3 OF lv_x.
    ENDIF.
    IF is_flags-request_non_nt_session_key = abap_true.
      SET BIT 2 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_target_info = abap_true.
      SET BIT 1 OF lv_x.
    ENDIF.
    rv_hex+2(1) = lv_x.

    CLEAR lv_x.
    IF is_flags-r4 = abap_true.
      SET BIT 1 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_version = abap_true.
      SET BIT 2 OF lv_x.
    ENDIF.
    IF is_flags-r3 = abap_true.
      SET BIT 3 OF lv_x.
    ENDIF.
    IF is_flags-r2 = abap_true.
      SET BIT 4 OF lv_x.
    ENDIF.
    IF is_flags-r1 = abap_true.
      SET BIT 5 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_128 = abap_true.
      SET BIT 6 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_key_exch = abap_true.
      SET BIT 7 OF lv_x.
    ENDIF.
    IF is_flags-negotiate_56 = abap_true.
      SET BIT 8 OF lv_x.
    ENDIF.
    rv_hex+3(1) = lv_x.

  ENDMETHOD.                    "flags_encode

  METHOD byte2_to_int.

    DATA: lv_rev TYPE zcl_ntlm=>ty_byte2.


    CONCATENATE iv_byte2+1(1) iv_byte2(1) INTO lv_rev IN BYTE MODE.
    rv_int = lv_rev.

  ENDMETHOD.                    "byte2_to_int

  METHOD byte4_to_int.

    DATA: lv_rev TYPE zcl_ntlm=>ty_byte4.


    CONCATENATE iv_byte4+3(1) iv_byte4+2(1) iv_byte4+1(1) iv_byte4(1)
      INTO lv_rev IN BYTE MODE.
    rv_int = lv_rev.

  ENDMETHOD.                    "byte4_to_int

  METHOD int_to_byte2.

    DATA: lv_rev TYPE zcl_ntlm=>ty_byte2.


    lv_rev = iv_int.
    rv_byte2(1) = lv_rev+1(1).
    rv_byte2+1(1) = lv_rev(1).

  ENDMETHOD.                    "int_to_byte2

  METHOD int_to_byte4.

    DATA: lv_rev TYPE zcl_ntlm=>ty_byte4.


    lv_rev = iv_int.
    rv_byte4(1) = lv_rev+3(1).
    rv_byte4+1(1) = lv_rev+2(1).
    rv_byte4+2(1) = lv_rev+1(1).
    rv_byte4+3(1) = lv_rev(1).

  ENDMETHOD.                    "int_to_byte4

ENDCLASS.                    "lcl_convert IMPLMENTATION.

*----------------------------------------------------------------------*
*       CLASS lcl_read DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_reader DEFINITION FINAL.

  PUBLIC SECTION.
    METHODS constructor
      IMPORTING iv_value TYPE string
                iv_type  TYPE xstring
      RAISING   zcx_ntlm_protocol_error.

    METHODS flags
      RETURNING
        VALUE(rs_flags) TYPE zcl_ntlm=>ty_flags.

    METHODS data_raw
      RETURNING
                VALUE(rv_data) TYPE xstring
      RAISING   zcx_ntlm_protocol_error.

    METHODS data_str
      IMPORTING
                iv_oem         TYPE abap_bool
      RETURNING
                VALUE(rv_data) TYPE string
      RAISING   zcx_ntlm_protocol_error.

    METHODS skip
      IMPORTING
        iv_bytes TYPE i.

    METHODS raw
      IMPORTING
        iv_bytes      TYPE i
      RETURNING
        VALUE(rv_raw) TYPE xstring.

  PRIVATE SECTION.
    DATA: mv_original TYPE xstring,
          mv_current  TYPE xstring.

ENDCLASS.                    "lcl_read DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_read IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_reader IMPLEMENTATION.

  METHOD raw.

    rv_raw = mv_current(iv_bytes).
    mv_current = mv_current+iv_bytes.

  ENDMETHOD.                    "raw

  METHOD skip.

    mv_current = mv_current+iv_bytes.

  ENDMETHOD.                    "skip

  METHOD constructor.

    mv_original = lcl_convert=>base64_decode( iv_value ).

    IF xstrlen( mv_original ) < 8 OR mv_original(8) <> zcl_ntlm=>c_signature.
      RAISE EXCEPTION TYPE zcx_ntlm_protocol_error.
    ENDIF.
    mv_current = mv_original+8.

    IF xstrlen( mv_current ) < 4 OR mv_current(4) <> iv_type.
      RAISE EXCEPTION TYPE zcx_ntlm_protocol_error.
    ENDIF.
    mv_current = mv_current+4.

  ENDMETHOD.                    "constructor

  METHOD flags.

    DATA: lv_byte4 TYPE zcl_ntlm=>ty_byte4.


    lv_byte4 = mv_current(4).
    rs_flags = lcl_convert=>flags_decode( lv_byte4 ).
    mv_current = mv_current+4.

  ENDMETHOD.                    "flags

  METHOD data_raw.

    DATA: lv_byte8  TYPE zcl_ntlm=>ty_byte8,
          ls_fields TYPE ty_fields.


    lv_byte8 = mv_current(8).
    ls_fields = lcl_convert=>fields_decode( lv_byte8 ).
    mv_current = mv_current+8.

    IF ls_fields-len = 0.
      RETURN.
    ENDIF.
    IF ls_fields-len <> ls_fields-maxlen.
      RAISE EXCEPTION TYPE zcx_ntlm_protocol_error.
    ENDIF.
    rv_data = mv_original+ls_fields-offset(ls_fields-len).

  ENDMETHOD.                    "fields

  METHOD data_str.

    DATA: lv_raw TYPE xstring.


    lv_raw = data_raw( ).
    IF iv_oem = abap_true.
      rv_data = lcl_convert=>codepage_utf_8_x( lv_raw ).
    ELSE.
      rv_data = lcl_convert=>codepage_4103_x( lv_raw ).
    ENDIF.

  ENDMETHOD.                    "data_str

ENDCLASS.                    "lcl_read IMPLEMENTATION

*----------------------------------------------------------------------*
*       CLASS lcl_write DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_writer DEFINITION FINAL.

  PUBLIC SECTION.
    METHODS constructor
      IMPORTING iv_type TYPE xstring.

    METHODS flags
      IMPORTING
        is_flags TYPE zcl_ntlm=>ty_flags.

    METHODS data_raw
      IMPORTING
        iv_data TYPE xsequence.

    METHODS data_str
      IMPORTING
        iv_oem  TYPE abap_bool DEFAULT abap_false
        iv_data TYPE clike.

    METHODS message
      RETURNING
        VALUE(rv_msg) TYPE string.

    METHODS raw
      IMPORTING
        iv_data TYPE xsequence.

  PRIVATE SECTION.
    TYPES: BEGIN OF ty_fix,
             fix    TYPE i,
             offset TYPE i,
             length TYPE i,
           END OF ty_fix.

    DATA: mv_header  TYPE xstring,
          mv_payload TYPE xstring,
          mt_fix     TYPE STANDARD TABLE OF ty_fix WITH EMPTY KEY.

ENDCLASS.                    "lcl_write DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_write IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_writer IMPLEMENTATION.

  METHOD message.

    DATA: lv_xstr   TYPE xstring,
          lv_fix    TYPE i,
          lv_len    TYPE i,
          lv_header TYPE x LENGTH 200,
          lv_offset TYPE i.

    FIELD-SYMBOLS: <ls_fix> LIKE LINE OF mt_fix.


    lv_len = xstrlen( mv_header ).
    ASSERT lv_len <= 200.
    lv_header = mv_header.
    lv_offset = xstrlen( mv_header ).
    LOOP AT mt_fix ASSIGNING <ls_fix>.
      lv_fix = <ls_fix>-fix.
      lv_header+lv_fix(4) = lcl_convert=>int_to_byte4( lv_offset ).
      lv_offset = lv_offset + <ls_fix>-length.
    ENDLOOP.
    mv_header = lv_header(lv_len).

    CONCATENATE mv_header mv_payload INTO lv_xstr IN BYTE MODE.

    rv_msg = lcl_convert=>base64_encode( lv_xstr ).

  ENDMETHOD.                    "message

  METHOD constructor.

    CONCATENATE zcl_ntlm=>c_signature iv_type INTO mv_header IN BYTE MODE.

  ENDMETHOD.                    "constructor

  METHOD flags.

    DATA: lv_byte4 TYPE zcl_ntlm=>ty_byte4.


    lv_byte4 = lcl_convert=>flags_encode( is_flags ).
    CONCATENATE mv_header lv_byte4 INTO mv_header IN BYTE MODE.

  ENDMETHOD.                    "flags

  METHOD data_raw.

    DATA: ls_fields TYPE ty_fields,
          ls_fix    LIKE LINE OF mt_fix,
          lv_byte8  TYPE zcl_ntlm=>ty_byte8.


    ls_fields-len = xstrlen( iv_data ).
    ls_fields-maxlen = xstrlen( iv_data ).

    ls_fix-fix = xstrlen( mv_header ) + 4.
    ls_fix-offset = xstrlen( mv_payload ).
    ls_fix-length = xstrlen( iv_data ).
    APPEND ls_fix TO mt_fix.

    lv_byte8 = lcl_convert=>fields_encode( ls_fields ).
    CONCATENATE mv_header lv_byte8 INTO mv_header IN BYTE MODE.

    CONCATENATE mv_payload iv_data INTO mv_payload IN BYTE MODE.

  ENDMETHOD.                    "fields

  METHOD raw.

    CONCATENATE mv_header iv_data INTO mv_header IN BYTE MODE.

  ENDMETHOD.                    "raw

  METHOD data_str.

    DATA: lv_raw TYPE xstring.


    IF iv_oem = abap_true.
      lv_raw = lcl_convert=>codepage_utf_8( iv_data ).
    ELSE.
      lv_raw = lcl_convert=>codepage_4103( iv_data ).
    ENDIF.

    data_raw( lv_raw ).

  ENDMETHOD.                    "data_str

ENDCLASS.                    "lcl_write IMPLEMENTATION
