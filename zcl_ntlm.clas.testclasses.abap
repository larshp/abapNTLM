CLASS lcl_test DEFINITION DEFERRED.
CLASS zcl_ntlm DEFINITION LOCAL FRIENDS lcl_test.

*----------------------------------------------------------------------*
*       CLASS lcl_Test DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS
  FINAL.

  PRIVATE SECTION.
* ================
    METHODS: base64_decode FOR TESTING,
             flags_encode  FOR TESTING,
             flags_decode  FOR TESTING.

ENDCLASS.       "lcl_Test

*----------------------------------------------------------------------*
*       CLASS lcl_Test IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test IMPLEMENTATION.
* ==============================

  METHOD base64_decode.

    DATA: lv_encoded TYPE string,
          lv_decoded TYPE xstring.


    lv_encoded = 'QUJBUCBpcyBjb29s'.

    lv_decoded = zcl_ntlm=>base64_decode( lv_encoded ).

    cl_abap_unit_assert=>assert_equals(
        exp = '4142415020697320636F6F6C'
        act = lv_decoded ).

  ENDMETHOD.                    "base64_decode

  METHOD flags_encode.

    DATA: lv_hex   TYPE zcl_ntlm=>ty_byte4,
          ls_flags TYPE zcl_ntlm=>ty_flags.


    ls_flags-negotiate_ntlm = abap_true.
    ls_flags-negotiate_oem = abap_true.

    lv_hex = zcl_ntlm=>flags_encode( ls_flags ).

    cl_abap_unit_assert=>assert_equals(
        exp = '02020000'
        act = lv_hex ).

  ENDMETHOD.                    "flags_encode

  METHOD flags_decode.

    DATA: ls_flags TYPE zcl_ntlm=>ty_flags.


    ls_flags = zcl_ntlm=>flags_decode( '02020000' ).

    cl_abap_unit_assert=>assert_equals(
        exp = abap_true
        act = ls_flags-negotiate_ntlm ).

    cl_abap_unit_assert=>assert_equals(
        exp = abap_true
        act = ls_flags-negotiate_oem ).

  ENDMETHOD.                    "flags_decode

ENDCLASS.       "lcl_Test