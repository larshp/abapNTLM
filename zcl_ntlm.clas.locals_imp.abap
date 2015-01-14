*"* use this source file for the definition and implementation of
*"* local helper classes, interface definitions and type
*"* declarations

  TYPES:
    BEGIN OF ty_flags,
           negotiate_56 TYPE abap_bool,
           negotiate_key_exch TYPE abap_bool,
           negotiate_128 TYPE abap_bool,
           r1 TYPE abap_bool,
           r2 TYPE abap_bool,
           r3 TYPE abap_bool,
           negotiate_version TYPE abap_bool,
           r4 TYPE abap_bool,
           negotiate_target_info TYPE abap_bool,
           request_non_nt_session_key TYPE abap_bool,
           r5 TYPE abap_bool,
           negotiate_identity TYPE abap_bool,
           negotiate_extended_session_sec TYPE abap_bool,
           r6 TYPE abap_bool,
           target_type_server TYPE abap_bool,
           target_type_domain TYPE abap_bool,
           negotiate_always_sign TYPE abap_bool,
           r7 TYPE abap_bool,
           negotiate_oem_workstation_sup TYPE abap_bool,
           negotiate_oem_domain_supplied TYPE abap_bool,
           anonymous TYPE abap_bool,
           r8 TYPE abap_bool,
           negotiate_ntlm TYPE abap_bool,
           r9 TYPE abap_bool,
           negotiate_lm_key TYPE abap_bool,
           negotiate_datagram TYPE abap_bool,
           negotiate_seal TYPE abap_bool,
           negotiate_sign TYPE abap_bool,
           r10 TYPE abap_bool,
           request_target TYPE abap_bool,
           negotiate_oem TYPE abap_bool,
           negotiate_unicode TYPE abap_bool,
         END OF ty_flags.

  TYPES:
    BEGIN OF ty_fields,
           len TYPE i,
           maxlen TYPE i,
           offset TYPE i,
         END OF ty_fields .

  TYPES: ty_byte2 TYPE x LENGTH 2.
  TYPES: ty_byte4 TYPE x LENGTH 4.
  TYPES: ty_byte8 TYPE x LENGTH 8.

*----------------------------------------------------------------------*
*       CLASS lcl_convert DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
  CLASS lcl_convert DEFINITION FINAL.

    PUBLIC SECTION.
      CLASS-METHODS fields_decode
        IMPORTING
          iv_byte8 TYPE ty_byte8
        RETURNING
          value(rs_fields) TYPE ty_fields .
      CLASS-METHODS fields_encode
        IMPORTING
          is_fields TYPE ty_fields
        RETURNING
          value(rv_byte8) TYPE ty_byte8 .
      CLASS-METHODS base64_decode
        IMPORTING
          iv_string TYPE string
        RETURNING
          value(rv_xstring) TYPE xstring .
      CLASS-METHODS base64_encode
        IMPORTING
          iv_xstring TYPE xstring
        RETURNING
          value(rv_string) TYPE string .
      CLASS-METHODS flags_decode
        IMPORTING
          iv_hex TYPE ty_byte4
        RETURNING
          value(rs_flags) TYPE ty_flags .
      CLASS-METHODS flags_encode
        IMPORTING
          is_flags TYPE ty_flags
        RETURNING
          value(rv_hex) TYPE ty_byte4 .
      CLASS-METHODS byte2_to_int
        IMPORTING
          iv_byte2 TYPE ty_byte2
        RETURNING
          value(rv_int) TYPE i .
      CLASS-METHODS byte4_to_int
        IMPORTING
          iv_byte4 TYPE ty_byte4
        RETURNING
          value(rv_int) TYPE i .
      CLASS-METHODS int_to_byte2
        IMPORTING
          iv_int TYPE i
        RETURNING
          value(rv_byte2) TYPE ty_byte2 .
      CLASS-METHODS int_to_byte4
        IMPORTING
          iv_int TYPE i
        RETURNING
          value(rv_byte4) TYPE ty_byte4 .
  ENDCLASS.                    "lcl_convert DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_convert IMPLMENTATION.
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
  CLASS lcl_convert IMPLEMENTATION.

    METHOD fields_decode.

      DATA: lv_byte2 TYPE ty_byte2,
            lv_byte4 TYPE ty_byte4.


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

      CALL FUNCTION 'SSFC_BASE64_DECODE'
        EXPORTING
          b64data                  = iv_string
        IMPORTING
          bindata                  = rv_xstring
        EXCEPTIONS
          ssf_krn_error            = 1
          ssf_krn_noop             = 2
          ssf_krn_nomemory         = 3
          ssf_krn_opinv            = 4
          ssf_krn_input_data_error = 5
          ssf_krn_invalid_par      = 6
          ssf_krn_invalid_parlen   = 7
          OTHERS                   = 8.
      IF sy-subrc <> 0.
        BREAK-POINT.
      ENDIF.

    ENDMETHOD.                    "base64_decode

    METHOD base64_encode.

      CALL FUNCTION 'SSFC_BASE64_ENCODE'
        EXPORTING
          bindata                  = iv_xstring
        IMPORTING
          b64data                  = rv_string
        EXCEPTIONS
          ssf_krn_error            = 1
          ssf_krn_noop             = 2
          ssf_krn_nomemory         = 3
          ssf_krn_opinv            = 4
          ssf_krn_input_data_error = 5
          ssf_krn_invalid_par      = 6
          ssf_krn_invalid_parlen   = 7
          OTHERS                   = 8.
      IF sy-subrc <> 0.
        BREAK-POINT.
      ENDIF.

    ENDMETHOD.                    "base64_encode

    METHOD flags_decode.

      DATA: lv_c TYPE c LENGTH 1,
            lv_x TYPE x LENGTH 1.

      DEFINE _flag.
        if lv_c = '1'.
          rs_flags-&1 = abap_true.
        endif.
      END-OF-DEFINITION.


      lv_x = iv_hex.
      GET BIT 8 OF lv_x INTO lv_c.
      _flag negotiate_unicode.
      GET BIT 7 OF lv_x INTO lv_c.
      _flag negotiate_oem.
      GET BIT 6 OF lv_x INTO lv_c.
      _flag request_target.
      GET BIT 5 OF lv_x INTO lv_c.
      _flag r10.
      GET BIT 4 OF lv_x INTO lv_c.
      _flag negotiate_sign.
      GET BIT 3 OF lv_x INTO lv_c.
      _flag negotiate_seal.
      GET BIT 2 OF lv_x INTO lv_c.
      _flag negotiate_datagram.
      GET BIT 1 OF lv_x INTO lv_c.
      _flag negotiate_lm_key.

      lv_x = iv_hex+1.
      GET BIT 8 OF lv_x INTO lv_c.
      _flag r9.
      GET BIT 7 OF lv_x INTO lv_c.
      _flag negotiate_ntlm.
      GET BIT 6 OF lv_x INTO lv_c.
      _flag r8.
      GET BIT 5 OF lv_x INTO lv_c.
      _flag anonymous.
      GET BIT 4 OF lv_x INTO lv_c.
      _flag negotiate_oem_domain_supplied.
      GET BIT 3 OF lv_x INTO lv_c.
      _flag negotiate_oem_workstation_sup.
      GET BIT 2 OF lv_x INTO lv_c.
      _flag r7.
      GET BIT 1 OF lv_x INTO lv_c.
      _flag negotiate_always_sign.

      lv_x = iv_hex+2.
      GET BIT 8 OF lv_x INTO lv_c.
      _flag target_type_domain.
      GET BIT 7 OF lv_x INTO lv_c.
      _flag target_type_server.
      GET BIT 6 OF lv_x INTO lv_c.
      _flag r6.
      GET BIT 5 OF lv_x INTO lv_c.
      _flag negotiate_extended_session_sec.
      GET BIT 4 OF lv_x INTO lv_c.
      _flag negotiate_identity.
      GET BIT 3 OF lv_x INTO lv_c.
      _flag r5.
      GET BIT 2 OF lv_x INTO lv_c.
      _flag request_non_nt_session_key.
      GET BIT 1 OF lv_x INTO lv_c.
      _flag negotiate_target_info.

      lv_x = iv_hex+3.
      GET BIT 1 OF lv_x INTO lv_c.
      _flag r4.
      GET BIT 2 OF lv_x INTO lv_c.
      _flag negotiate_version.
      GET BIT 3 OF lv_x INTO lv_c.
      _flag r3.
      GET BIT 4 OF lv_x INTO lv_c.
      _flag r2.
      GET BIT 5 OF lv_x INTO lv_c.
      _flag r1.
      GET BIT 6 OF lv_x INTO lv_c.
      _flag negotiate_128.
      GET BIT 7 OF lv_x INTO lv_c.
      _flag negotiate_key_exch.
      GET BIT 8 OF lv_x INTO lv_c.
      _flag negotiate_56.

    ENDMETHOD.                    "flags_decode

    METHOD flags_encode.

      DATA: lv_c TYPE c LENGTH 1,
            lv_x TYPE x LENGTH 1.

      DEFINE _flag.
        if is_flags-&1 = abap_true.
          lv_c = '1'.
        else.
          lv_c = '0'.
        endif.
      END-OF-DEFINITION.


      CLEAR lv_x.
      _flag negotiate_unicode.
      SET BIT 8 OF lv_x TO lv_c.
      _flag negotiate_oem.
      SET BIT 7 OF lv_x TO lv_c.
      _flag request_target.
      SET BIT 6 OF lv_x TO lv_c.
      _flag r10.
      SET BIT 5 OF lv_x TO lv_c.
      _flag negotiate_sign.
      SET BIT 4 OF lv_x TO lv_c.
      _flag negotiate_seal.
      SET BIT 3 OF lv_x TO lv_c.
      _flag negotiate_datagram.
      SET BIT 2 OF lv_x TO lv_c.
      _flag negotiate_lm_key.
      SET BIT 1 OF lv_x TO lv_c.
      rv_hex(1) = lv_x.

      CLEAR lv_x.
      _flag r9.
      SET BIT 8 OF lv_x TO lv_c.
      _flag negotiate_ntlm.
      SET BIT 7 OF lv_x TO lv_c.
      _flag r8.
      SET BIT 6 OF lv_x TO lv_c.
      _flag anonymous.
      SET BIT 5 OF lv_x TO lv_c.
      _flag negotiate_oem_domain_supplied.
      SET BIT 4 OF lv_x TO lv_c.
      _flag negotiate_oem_workstation_sup.
      SET BIT 3 OF lv_x TO lv_c.
      _flag r7.
      SET BIT 2 OF lv_x TO lv_c.
      _flag negotiate_always_sign.
      SET BIT 1 OF lv_x TO lv_c.
      rv_hex+1(1) = lv_x.

      CLEAR lv_x.
      _flag target_type_domain.
      SET BIT 8 OF lv_x TO lv_c.
      _flag target_type_server.
      SET BIT 7 OF lv_x TO lv_c.
      _flag r6.
      SET BIT 6 OF lv_x TO lv_c.
      _flag negotiate_extended_session_sec.
      SET BIT 5 OF lv_x TO lv_c.
      _flag negotiate_identity.
      SET BIT 4 OF lv_x TO lv_c.
      _flag r5.
      SET BIT 3 OF lv_x TO lv_c.
      _flag request_non_nt_session_key.
      SET BIT 2 OF lv_x TO lv_c.
      _flag negotiate_target_info.
      SET BIT 1 OF lv_x TO lv_c.
      rv_hex+2(1) = lv_x.

      CLEAR lv_x.
      _flag r4.
      SET BIT 1 OF lv_x TO lv_c.
      _flag negotiate_version.
      SET BIT 2 OF lv_x TO lv_c.
      _flag r3.
      SET BIT 3 OF lv_x TO lv_c.
      _flag r2.
      SET BIT 4 OF lv_x TO lv_c.
      _flag r1.
      SET BIT 5 OF lv_x TO lv_c.
      _flag negotiate_128.
      SET BIT 6 OF lv_x TO lv_c.
      _flag negotiate_key_exch.
      SET BIT 7 OF lv_x TO lv_c.
      _flag negotiate_56.
      SET BIT 8 OF lv_x TO lv_c.
      rv_hex+3(1) = lv_x.

    ENDMETHOD.                    "flags_encode

    METHOD byte2_to_int.

      DATA: lv_rev TYPE ty_byte2.


      CONCATENATE iv_byte2+1(1) iv_byte2(1) INTO lv_rev IN BYTE MODE.
      rv_int = lv_rev.

    ENDMETHOD.                    "byte2_to_int

    METHOD byte4_to_int.

      DATA: lv_rev TYPE ty_byte4.


      CONCATENATE iv_byte4+3(1) iv_byte4+2(1) iv_byte4+1(1) iv_byte4(1)
        INTO lv_rev IN BYTE MODE.
      rv_int = lv_rev.

    ENDMETHOD.                    "byte4_to_int

    METHOD int_to_byte2.

      DATA: lv_rev TYPE ty_byte2.


      lv_rev = iv_int.
      rv_byte2(1) = lv_rev+1(1).
      rv_byte2+1(1) = lv_rev(1).

    ENDMETHOD.                    "int_to_byte2

    METHOD int_to_byte4.

      DATA: lv_rev TYPE ty_byte4.


      lv_rev = iv_int.
      rv_byte4(1)   = lv_rev+3(1).
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
  CLASS lcl_read DEFINITION FINAL.

    PUBLIC SECTION.
      CLASS-METHODS flags
        EXPORTING
          es_flags TYPE ty_flags
        CHANGING
          cv_xstr TYPE xstring.

      CLASS-METHODS fields
        EXPORTING
          es_fields TYPE ty_fields
        CHANGING
          cv_xstr TYPE xstring.

      CLASS-METHODS signature
        IMPORTING
          iv_value TYPE string
          iv_type TYPE xstring
        CHANGING
          cv_xstr TYPE xstring.

  ENDCLASS.                    "lcl_read DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_read IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
  CLASS lcl_read IMPLEMENTATION.

    METHOD flags.

      DATA: lv_byte4 TYPE ty_byte4.


      lv_byte4 = cv_xstr(4).
      es_flags = lcl_convert=>flags_decode( lv_byte4 ).
      cv_xstr = cv_xstr+4.

    ENDMETHOD.                    "flags

    METHOD fields.

      DATA: lv_byte8 TYPE ty_byte8.


      lv_byte8 = cv_xstr(8).
      es_fields = lcl_convert=>fields_decode( lv_byte8 ).
      cv_xstr = cv_xstr+8.

    ENDMETHOD.                    "fields

    METHOD signature.

      cv_xstr = lcl_convert=>base64_decode( iv_value ).

      IF xstrlen( cv_xstr ) < 8 OR cv_xstr(8) <> zcl_ntlm=>c_signature.
        BREAK-POINT.
      ENDIF.
      cv_xstr = cv_xstr+8.

      IF xstrlen( cv_xstr ) < 4 OR cv_xstr(4) <> iv_type.
        BREAK-POINT.
      ENDIF.
      cv_xstr = cv_xstr+4.

    ENDMETHOD.                    "signature

  ENDCLASS.                    "lcl_read IMPLEMENTATION

*----------------------------------------------------------------------*
*       CLASS lcl_write DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
  CLASS lcl_write DEFINITION FINAL.

    PUBLIC SECTION.
      CLASS-METHODS flags
        IMPORTING
          is_flags TYPE ty_flags
        CHANGING
          cv_xstr TYPE xstring.

      CLASS-METHODS fields
        IMPORTING
          is_fields TYPE ty_fields
        CHANGING
          cv_xstr TYPE xstring.

      CLASS-METHODS signature
        IMPORTING
          iv_type TYPE xstring
        RETURNING
          value(rv_xstr) TYPE xstring.

  ENDCLASS.                    "lcl_write DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_write IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
  CLASS lcl_write IMPLEMENTATION.

    METHOD flags.

      DATA: lv_byte4 TYPE ty_byte4.


      lv_byte4 = lcl_convert=>flags_encode( is_flags ).
      CONCATENATE cv_xstr lv_byte4 INTO cv_xstr IN BYTE MODE.

    ENDMETHOD.                    "flags

    METHOD fields.

      DATA: lv_byte8 TYPE ty_byte8.


      lv_byte8 = lcl_convert=>fields_encode( is_fields ).
      CONCATENATE cv_xstr lv_byte8 INTO cv_xstr IN BYTE MODE.

    ENDMETHOD.                    "fields

    METHOD signature.

      CONCATENATE zcl_ntlm=>c_signature iv_type INTO rv_xstr IN BYTE MODE.

    ENDMETHOD.                    "signature

  ENDCLASS.                    "lcl_write IMPLEMENTATION