CLASS lcl_test DEFINITION DEFERRED.
CLASS zcl_ntlm DEFINITION LOCAL FRIENDS lcl_test.

  CLASS lcl_convert_test DEFINITION DEFERRED.
CLASS zcl_ntlm DEFINITION LOCAL FRIENDS lcl_convert_test.

*----------------------------------------------------------------------*
*       CLASS lcl_test DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS
  FINAL.

  PRIVATE SECTION.
* ================
    METHODS: type_1_decode   FOR TESTING,
             type_1_encode   FOR TESTING,
             type_2_decode   FOR TESTING,
             type_2_encode   FOR TESTING,
             type_3_decode   FOR TESTING,
             type_3_encode   FOR TESTING RAISING cx_static_check,
             lmv1_response   FOR TESTING,
             ntlmv1_response FOR TESTING,
             ntlmv2_response FOR TESTING RAISING cx_static_check.

ENDCLASS.                    "lcl_test DEFINITION

*----------------------------------------------------------------------*
*       CLASS lcl_test IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test IMPLEMENTATION.

  METHOD lmv1_response.

    DATA: lv_response TYPE xstring.


    lv_response = zcl_ntlm=>lmv1_response(
      iv_password  = 'secret01'
      iv_challenge = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = 'C337CD5CBD44FC9782A667AF6D427C6DE67C20C2D3E77C56'
      act  = lv_response
      quit = if_aunit_constants=>no ).

    lv_response = zcl_ntlm=>lmv1_response(
      iv_password  = 'Password'
      iv_challenge = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13'
      act  = lv_response
      quit = if_aunit_constants=>no ).

  ENDMETHOD.                    "lmv1_response

  METHOD ntlmv2_response.

    DATA: lv_info     TYPE xstring,
          lv_response TYPE xstring.


    lv_info = '02000C0044004F004D00410049004E00' &&
              '01000C00530045005200560045005200' &&
              '0400140064006F006D00610069006E00' &&
              '2E0063006F006D000300220073006500' &&
              '72007600650072002E0064006F006D00' &&
              '610069006E002E0063006F006D000000' &&
              '0000'.

    lv_response = zcl_ntlm=>ntlmv2_response(
      iv_password  = 'SecREt01'
      iv_username  = 'user'
      iv_target    = 'DOMAIN'
      iv_challenge = '0123456789ABCDEF'
      iv_info      = lv_info ).

    cl_abap_unit_assert=>assert_not_initial( lv_response ).

  ENDMETHOD.                    "ntmlv2_response

  METHOD ntlmv1_response.

    DATA: lv_response TYPE zcl_ntlm=>ty_byte24.


    lv_response = zcl_ntlm=>ntlmv1_response(
        iv_password  = 'SecREt01'
        iv_challenge = '0123456789ABCDEF' ).

    cl_abap_unit_assert=>assert_equals(
      exp  = '25A98C1C31E81847466B29B2DF4680F39958FB8C213A9CC6'
      act  = lv_response
      quit = if_aunit_constants=>no ).

    lv_response = zcl_ntlm=>ntlmv1_response(
        iv_password  = 'Password'
        iv_challenge = '0123456789ABCDEF' ).

    cl_abap_unit_assert=>assert_equals(
      exp  = '67C43011F30298A2AD35ECE64F16331C44BDBED927841F94'
      act  = lv_response
      quit = if_aunit_constants=>no ).

  ENDMETHOD.                    "ntlm_response

  METHOD type_1_decode.

    DATA: lv_value TYPE string.


    RETURN.
    lv_value = ''.

    zcl_ntlm=>type_1_decode( lv_value ).

  ENDMETHOD.                    "type_1_decode

  METHOD type_1_encode.

    DATA: lv_msg TYPE string.


    lv_msg = zcl_ntlm=>type_1_encode( ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'TlRMTVNTUAABAAAAAQIAAA=='
        act = lv_msg ).

  ENDMETHOD.                    "type_1_encode

  METHOD type_2_decode.

    DATA: lv_value TYPE string,
          lv_xstr  TYPE xstring.


    lv_value = 'TlRMTVNTUAACAAAADAAMADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAA' &&
               'RABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZA' &&
               'BvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAu' &&
               'AGMAbwBtAAAAAAA='.
    zcl_ntlm=>type_2_decode( lv_value ).


    lv_xstr = '4E544C4D53535000020000000C000C00' &&
              '38000000338202E20123456789ABCDEF' &&
              '00000000000000000000000000000000' &&
              '060070170000000F5300650072007600' &&
              '65007200'.
    lv_value = lcl_convert=>base64_encode( lv_xstr ).
    zcl_ntlm=>type_2_decode( lv_value ).


  ENDMETHOD.                    "type_2_decode

  METHOD type_2_encode.

    zcl_ntlm=>type_2_encode( ).

  ENDMETHOD.                    "type_2_encode

  METHOD type_3_decode.

    DATA: lv_raw TYPE xstring,
          lv_value TYPE string.


    lv_value = 'TlRMTVNTUAADAAAAGAAYAGoAAAAYABgAggAAAAwADABAAAAACAAIAEwAAAAWABYAVA' &&
               'AAAAAAAACaAAAAAQIAAEQATwBNAEEASQBOAHUAcwBlAHIAVwBPAFIASwBTAFQAQQBU' &&
               'AEkATwBOAMM3zVy9RPyXgqZnr21CfG3mfCDC0+d8ViWpjBwx6BhHRmspst9GgPOZWP' &&
               'uMITqcxg=='.
    zcl_ntlm=>type_3_decode( lv_value ).

    lv_raw = '4E544C4D535350000300000018001800' &&
             '6C00000018001800840000000C000C00' &&
             '48000000080008005400000010001000' &&
             '5C000000100010009C000000358280E2' &&
             '0501280A0000000F44006F006D006100' &&
             '69006E00550073006500720043004F00' &&
             '4D005000550054004500520098DEF7B8' &&
             '7F88AA5DAFE2DF779688A172DEF11C7D' &&
             '5CCDEF1367C43011F30298A2AD35ECE6' &&
             '4F16331C44BDBED927841F94518822B1' &&
             'B3F350C8958682ECBB3E3CB7'.
    lv_value = lcl_convert=>base64_encode( lv_raw ).
    zcl_ntlm=>type_3_decode( lv_value ).

  ENDMETHOD.                    "type_3_decode

  METHOD type_3_encode.

    DATA: lv_expected TYPE xstring,
          lv_response TYPE xstring.


    lv_expected = '4E544C4D535350000300000018001800' &&
                  '6C00000018001800840000000C000C00' &&
                  '48000000080008005400000010001000' &&
                  '5C000000100010009C000000358280E2' &&
                  '0501280A0000000F44006F006D006100' &&
                  '69006E00550073006500720043004F00' &&
                  '4D005000550054004500520098DEF7B8' &&
                  '7F88AA5DAFE2DF779688A172DEF11C7D' &&
                  '5CCDEF1367C43011F30298A2AD35ECE6' &&
                  '4F16331C44BDBED927841F94518822B1' &&
                  'B3F350C8958682ECBB3E3CB7'.
    lv_response = zcl_ntlm=>type_3_encode( iv_password = 'Password'
                                           iv_challenge = '0123456789ABCDEF' ).

* todo
*    cl_abap_unit_assert=>assert_equals(
*        exp = lv_response
*        act = lv_expected ).

  ENDMETHOD.                    "type_3_encode

ENDCLASS.                    "lcl_test IMPLEMENTATION

*----------------------------------------------------------------------*
*       CLASS lcl_Test DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_convert_test DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS
  FINAL.

  PRIVATE SECTION.
* ================
    METHODS: base64_encode  FOR TESTING,
             base64_decode  FOR TESTING,
             flags_encode   FOR TESTING,
             flags_decode   FOR TESTING,
             fields_encode  FOR TESTING,
             fields_decode1 FOR TESTING,
             fields_decode2 FOR TESTING,
             byte2          FOR TESTING,
             byte4_1        FOR TESTING,
             byte4_2        FOR TESTING.

ENDCLASS.       "lcl_Test

*----------------------------------------------------------------------*
*       CLASS lcl_Test IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_convert_test IMPLEMENTATION.
* ==============================

  METHOD base64_encode.

    CONSTANTS lc_foo TYPE xstring VALUE 'ABC123'.


    cl_abap_unit_assert=>assert_equals(
        exp = lc_foo
        act = lcl_convert=>base64_decode(
              lcl_convert=>base64_encode( lc_foo ) ) ).

  ENDMETHOD.                    "base64_encode

  METHOD base64_decode.

    DATA: lv_encoded TYPE string,
          lv_decoded TYPE xstring.


    lv_encoded = 'QUJBUCBpcyBjb29s'.

    lv_decoded = lcl_convert=>base64_decode( lv_encoded ).

    cl_abap_unit_assert=>assert_equals(
        exp = '4142415020697320636F6F6C'
        act = lv_decoded ).

  ENDMETHOD.                    "base64_decode

  METHOD flags_encode.

    DATA: lv_hex   TYPE zcl_ntlm=>ty_byte4,
          ls_flags TYPE zcl_ntlm=>ty_flags.


    ls_flags-negotiate_ntlm = abap_true.
    ls_flags-negotiate_oem = abap_true.

    lv_hex = lcl_convert=>flags_encode( ls_flags ).

    cl_abap_unit_assert=>assert_equals(
        exp = '02020000'
        act = lv_hex ).

  ENDMETHOD.                    "flags_encode

  METHOD flags_decode.

    DATA: ls_flags TYPE zcl_ntlm=>ty_flags.


    ls_flags = lcl_convert=>flags_decode( '02020000' ).

    cl_abap_unit_assert=>assert_equals(
        exp = abap_true
        act = ls_flags-negotiate_ntlm ).

    cl_abap_unit_assert=>assert_equals(
        exp = abap_true
        act = ls_flags-negotiate_oem ).

  ENDMETHOD.                    "flags_decode

  METHOD fields_encode.

    DATA: ls_fields TYPE ty_fields.


    ls_fields-len = 100.
    ls_fields-maxlen = 200.
    ls_fields-offset = 550000.

    cl_abap_unit_assert=>assert_equals(
        exp = ls_fields
        act = lcl_convert=>fields_decode(
              lcl_convert=>fields_encode( ls_fields ) ) ).

  ENDMETHOD.                    "fields_encode

  METHOD fields_decode1.

    DATA: ls_fields TYPE ty_fields.


    ls_fields = lcl_convert=>fields_decode( '0C000C0030000000' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 12
        act = ls_fields-len ).
    cl_abap_unit_assert=>assert_equals(
        exp = 12
        act = ls_fields-maxlen ).
    cl_abap_unit_assert=>assert_equals(
        exp = 48
        act = ls_fields-offset ).

  ENDMETHOD.                    "fields_decode

  METHOD fields_decode2.

    DATA: ls_fields TYPE ty_fields.


    ls_fields = lcl_convert=>fields_decode( '620062003C000000' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 98
        act = ls_fields-len ).
    cl_abap_unit_assert=>assert_equals(
        exp = 98
        act = ls_fields-maxlen ).
    cl_abap_unit_assert=>assert_equals(
        exp = 60
        act = ls_fields-offset ).

  ENDMETHOD.                    "fields_decode2

  METHOD byte2.

    CONSTANTS: lc_int TYPE i VALUE 9568.


    cl_abap_unit_assert=>assert_equals(
        exp = lc_int
        act = lcl_convert=>byte2_to_int(
              lcl_convert=>int_to_byte2( lc_int ) ) ).

  ENDMETHOD.                    "byte2

  METHOD byte4_1.

    CONSTANTS: lc_int TYPE i VALUE 9568.


    cl_abap_unit_assert=>assert_equals(
        exp = lc_int
        act = lcl_convert=>byte4_to_int(
              lcl_convert=>int_to_byte4( lc_int ) ) ).

  ENDMETHOD.                    "byte4

  METHOD byte4_2.

    CONSTANTS: lc_int TYPE i VALUE 109568.


    cl_abap_unit_assert=>assert_equals(
        exp = lc_int
        act = lcl_convert=>byte4_to_int(
              lcl_convert=>int_to_byte4( lc_int ) ) ).

  ENDMETHOD.                    "byte4_2

ENDCLASS.       "lcl_Test