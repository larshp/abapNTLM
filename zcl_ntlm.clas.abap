class ZCL_NTLM definition
  public
  final
  create public .

public section.
*"* public components of class ZCL_NTLM
*"* do not include other source files here!!!

  class-methods GET
    importing
      !IV_USERNAME type CLIKE
      !IV_PASSWORD type CLIKE
      !IV_DOMAIN type CLIKE
      !IV_WORKSTATION type CLIKE
      !IV_URL type CLIKE
      !IV_SSL_ID type SSFAPPLSSL default 'ANONYM'
    returning
      value(RI_CLIENT) type ref to IF_HTTP_CLIENT
    raising
      CX_STATIC_CHECK .
protected section.
*"* protected components of class ZCL_NTLM
*"* do not include other source files here!!!

  types:
    ty_byte2 TYPE x LENGTH 2 .
  types:
    ty_byte4 TYPE x LENGTH 4 .
  types:
    ty_byte8 TYPE x LENGTH 8 .
  types:
    ty_byte16 TYPE x LENGTH 16 .
  types:
    ty_byte24 TYPE x LENGTH 24 .
  types:
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
         END OF ty_flags .
  types:
    BEGIN OF ty_type1,
      flags type ty_flags,
      target_name TYPE string,
      workstation TYPE string,
      version type ty_byte8,
    END OF ty_type1 .
  types:
    begin of TY_TYPE2,
      target_name type string,
      flags type ty_flags,
      challenge type ty_byte8,
      target_info type xstring,
    end of ty_type2 .
  types:
    begin of TY_TYPE3,
      lm_resp type xstring,
      ntlm_resp type xstring,
      target_name type string,
      user_name type string,
      workstation type string,
      session_key type xstring,
      flags type ty_flags,
      version type ty_byte8,
    end of ty_type3 .

  constants C_MESSAGE_TYPE_1 type XSTRING value '01000000'. "#EC NOTEXT
  constants C_SIGNATURE type XSTRING value '4E544C4D53535000'. "#EC NOTEXT
  constants C_MESSAGE_TYPE_2 type XSTRING value '02000000'. "#EC NOTEXT
  constants C_MESSAGE_TYPE_3 type XSTRING value '03000000'. "#EC NOTEXT

  class-methods NTLM2_SESSION_RESPONSE
    importing
      !IV_NONCE type TY_BYTE8
      !IV_CHALLENGE type TY_BYTE8
      !IV_PASSWORD type CLIKE
    exporting
      !EV_LM_RESPONSE type XSTRING
      !EV_NTLM_RESPONSE type XSTRING .
  class-methods NTLMV2_HASH
    importing
      !IV_PASSWORD type CLIKE
      !IV_USERNAME type CLIKE
      !IV_TARGET type CLIKE
    returning
      value(RV_HASH) type TY_BYTE16
    raising
      CX_STATIC_CHECK .
  class-methods HTTP_1
    importing
      !IV_URL type CLIKE
      !IV_SSL_ID type SSFAPPLSSL
    returning
      value(RI_CLIENT) type ref to IF_HTTP_CLIENT .
  class-methods HTTP_2
    importing
      !IV_AUTHORIZATION type STRING
      !II_CLIENT type ref to IF_HTTP_CLIENT
    returning
      value(RV_AUTHORIZATION) type STRING .
  class-methods LMV2_RESPONSE
    importing
      !IV_PASSWORD type CLIKE
      !IV_DOMAIN type CLIKE
      !IV_USERNAME type CLIKE
      !IV_CHALLENGE type TY_BYTE8
      !IV_NONCE type TY_BYTE8
    returning
      value(RV_RESPONSE) type TY_BYTE24
    raising
      CX_STATIC_CHECK .
  class-methods TYPE_3_BUILD
    importing
      !IV_USERNAME type CLIKE
      !IV_PASSWORD type CLIKE
      !IV_DOMAIN type CLIKE
      !IV_WORKSTATION type CLIKE
      !IS_DATA2 type TY_TYPE2
    returning
      value(RS_DATA3) type TY_TYPE3
    raising
      CX_STATIC_CHECK .
  class-methods SESSION_KEY
    importing
      !IV_PASSWORD type CLIKE
    returning
      value(RV_SESSION_KEY) type XSTRING
    raising
      CX_STATIC_CHECK .
  class-methods LMV1_RESPONSE
    importing
      !IV_PASSWORD type CLIKE
      !IV_CHALLENGE type TY_BYTE8
    returning
      value(RV_RESPONSE) type XSTRING .
  class-methods NTLMV2_RESPONSE
    importing
      !IV_PASSWORD type CLIKE
      !IV_USERNAME type CLIKE
      !IV_TARGET type CLIKE
      !IV_CHALLENGE type TY_BYTE8
      !IV_INFO type XSTRING
      !IV_NONCE type TY_BYTE8
      !IV_TIME type TY_BYTE8 optional
    returning
      value(RV_RESPONSE) type XSTRING
    raising
      CX_STATIC_CHECK .
  class-methods NTLMV1_RESPONSE
    importing
      !IV_PASSWORD type CLIKE
      !IV_CHALLENGE type TY_BYTE8
    returning
      value(RV_RESPONSE) type TY_BYTE24 .
  class-methods TYPE_1_DECODE
    importing
      !IV_MSG type STRING
    returning
      value(RS_DATA) type TY_TYPE1 .
  class-methods TYPE_2_ENCODE
    importing
      !IS_DATA type TY_TYPE2
    returning
      value(RV_MSG) type STRING .
  type-pools ABAP .
  class-methods TYPE_3_DECODE
    importing
      !IV_MSG type STRING
      !IV_OEM type ABAP_BOOL default ABAP_FALSE
    returning
      value(RS_DATA) type TY_TYPE3 .
  class-methods TYPE_1_ENCODE
    importing
      !IS_DATA type TY_TYPE1
    returning
      value(RV_MSG) type STRING .
  class-methods TYPE_2_DECODE
    importing
      !IV_MSG type STRING
      !IV_OEM type ABAP_BOOL default ABAP_FALSE
    returning
      value(RS_DATA) type TY_TYPE2 .
  class-methods TYPE_3_ENCODE
    importing
      !IS_DATA type TY_TYPE3
    returning
      value(RV_MSG) type STRING
    raising
      CX_STATIC_CHECK .
private section.
*"* private components of class ZCL_NTLM
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_NTLM IMPLEMENTATION.


METHOD get.

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

* https://msdn.microsoft.com/en-us/library/cc236621.aspx
* http://davenport.sourceforge.net/ntlm.html
* http://blogs.msdn.com/b/chiranth/archive/2013/09/21/ntlm-want-to-know-how-it-works.aspx
* http://www.innovation.ch/personal/ronald/ntlm.html

  DATA: lv_value  TYPE string,
        ls_data1  TYPE ty_type1,
        ls_data2  TYPE ty_type2,
        ls_data3  TYPE ty_type3.


  ri_client = http_1( iv_url    = iv_url
                      iv_ssl_id = iv_ssl_id ).

* build type 1 message
**  ls_data1-flags-negotiate_key_exch = abap_true.
*  ls_data1-flags-negotiate_target_info = abap_true.
*  ls_data1-flags-negotiate_ntlm     = abap_true.
*  ls_data1-flags-negotiate_unicode  = abap_true.
  ls_data1-flags-r3 = abap_true.
  ls_data1-flags-negotiate_extended_session_sec = abap_true.
  ls_data1-flags-negotiate_ntlm = abap_true.
  ls_data1-flags-negotiate_seal = abap_true.
  ls_data1-flags-negotiate_sign = abap_true.
  ls_data1-flags-request_target = abap_true.
  ls_data1-flags-negotiate_unicode = abap_true.

  ls_data1-target_name = iv_domain.
  ls_data1-workstation = iv_workstation.

  lv_value = type_1_encode( ls_data1 ).
  CONCATENATE 'NTLM' lv_value INTO lv_value SEPARATED BY space.

  lv_value = http_2( iv_authorization = lv_value
                     ii_client        = ri_client ).

  IF strlen( lv_value ) <= 5.
    BREAK-POINT.
    RETURN.
  ENDIF.

* decode type 2 message
  lv_value = lv_value+5.
  ls_data2 = type_2_decode( lv_value ).

* build type 3 message
  ls_data3 = type_3_build( iv_username = iv_username
                           iv_password = iv_password
                           iv_domain   = iv_domain
                           iv_workstation = iv_workstation
                           is_data2    = ls_data2 ).
  lv_value = type_3_encode( ls_data3 ).
  CONCATENATE 'NTLM' lv_value INTO lv_value SEPARATED BY space.

  http_2( iv_authorization = lv_value
          ii_client        = ri_client ).

ENDMETHOD.


METHOD http_1.

  DATA: lt_fields TYPE tihttpnvp,
        lv_url    TYPE string.

  FIELD-SYMBOLS: <ls_field> LIKE LINE OF lt_fields.


  lv_url = iv_url. " convert type
  cl_http_client=>create_by_url(
    EXPORTING
      url    = lv_url
      ssl_id = iv_ssl_id
    IMPORTING
      client = ri_client ).

  ri_client->propertytype_logon_popup = ri_client->co_disabled.

  ri_client->send( ).
  ri_client->receive(
    EXCEPTIONS
      http_communication_failure = 1
      http_invalid_state         = 2
      http_processing_failed     = 3
      OTHERS                     = 4 ).
  IF sy-subrc <> 0.
* todo
    BREAK-POINT.
  ENDIF.

  ri_client->response->get_header_fields( CHANGING fields = lt_fields ).

  READ TABLE lt_fields ASSIGNING <ls_field>
    WITH KEY name = 'www-authenticate' value = 'NTLM'.      "#EC NOTEXT
  IF sy-subrc <> 0.
* no NTML destination
    BREAK-POINT.
  ENDIF.

ENDMETHOD.


METHOD http_2.

  DATA: lt_fields TYPE tihttpnvp.

  FIELD-SYMBOLS: <ls_field> LIKE LINE OF lt_fields.


  ii_client->request->set_header_field(
      name  = 'authorization'
      value = iv_authorization ).                           "#EC NOTEXT

  ii_client->send( ).
  ii_client->receive(
    EXCEPTIONS
      http_communication_failure = 1
      http_invalid_state         = 2
      http_processing_failed     = 3
      OTHERS                     = 4 ).
  IF sy-subrc <> 0.
* todo
    BREAK-POINT.
  ENDIF.

  ii_client->response->get_header_fields( CHANGING fields = lt_fields ).

  READ TABLE lt_fields ASSIGNING <ls_field>
    WITH KEY name = 'www-authenticate'.                     "#EC NOTEXT
  IF sy-subrc <> 0.
* no NTML destination
    BREAK-POINT.
  ENDIF.

  rv_authorization = <ls_field>-value.

ENDMETHOD.


METHOD lmv1_response.

  CONSTANTS: lc_text TYPE xstring VALUE '4B47532140232425'. " KGS!@#$%

  DATA: lv_pass TYPE xstring,
        lv_lm_hash TYPE x LENGTH 21,
        lv_rd1  TYPE x LENGTH 7,
        lv_rd2  TYPE x LENGTH 7,
        lv_rd3  TYPE x LENGTH 7,
        lv_r1   TYPE x LENGTH 8,
        lv_r2   TYPE x LENGTH 8,
        lv_r3   TYPE x LENGTH 8.


  lv_pass = lcl_convert=>codepage_utf_8( to_upper( iv_password ) ).
* todo, special characters?
  lv_rd1 = lv_pass.
  lv_rd2 = lv_pass+7.

  lv_r1 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd1 )
      iv_plaintext = lc_text ).
  lv_r2 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd2 )
      iv_plaintext = lc_text ).

  CONCATENATE lv_r1 lv_r2 INTO lv_lm_hash IN BYTE MODE.

  lv_rd1 = lv_lm_hash.
  lv_rd2 = lv_lm_hash+7.
  lv_rd3 = lv_lm_hash+14.

  lv_r1 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd1 )
      iv_plaintext = iv_challenge ).
  lv_r2 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd2 )
      iv_plaintext = iv_challenge ).
  lv_r3 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd3 )
      iv_plaintext = iv_challenge ).

  CONCATENATE lv_r1 lv_r2 lv_r3 INTO rv_response IN BYTE MODE.

ENDMETHOD.


METHOD lmv2_response.

  DATA: lv_v2hash TYPE ty_byte16,
        lv_data   TYPE xstring.


  lv_v2hash = ntlmv2_hash( iv_password = iv_password
                           iv_username = iv_username
                           iv_target   = iv_domain ).

  CONCATENATE iv_challenge iv_nonce INTO lv_data IN BYTE MODE.

  lv_data = lcl_util=>hmac_md5( iv_key  = lv_v2hash
                                iv_data = lv_data ).

  CONCATENATE lv_data iv_nonce INTO rv_response IN BYTE MODE.

ENDMETHOD.


METHOD ntlm2_session_response.

  CONSTANTS: lc_zero TYPE x LENGTH 16 VALUE '00000000000000000000000000000000'.

  DATA: lv_snonce TYPE xstring,
        lv_md5    TYPE ty_byte16,
        lv_md4    TYPE ty_byte16,
        lv_shash  TYPE ty_byte8,
        lv_rd1    TYPE x LENGTH 7,
        lv_rd2    TYPE x LENGTH 7,
        lv_rd3    TYPE x LENGTH 7,
        lv_r1     TYPE x LENGTH 8,
        lv_r2     TYPE x LENGTH 8,
        lv_r3     TYPE x LENGTH 8.


  CONCATENATE iv_nonce lc_zero INTO ev_lm_response IN BYTE MODE.

  CONCATENATE iv_challenge iv_nonce INTO lv_snonce IN BYTE MODE.

  lv_md5 = lcl_util=>md5( lv_snonce ).
  lv_shash = lv_md5(8).

  lv_md4 = zcl_md4=>hash( iv_string   = iv_password
                          iv_encoding = '4103' ).

  lv_rd1 = lv_md4.
  lv_rd2 = lv_md4+7.
  lv_rd3 = lv_md4+14.

  lv_r1 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd1 )
      iv_plaintext = lv_shash ).
  lv_r2 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd2 )
      iv_plaintext = lv_shash ).
  lv_r3 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd3 )
      iv_plaintext = lv_shash ).

  CONCATENATE lv_r1 lv_r2 lv_r3 INTO ev_ntlm_response IN BYTE MODE.

ENDMETHOD.


METHOD ntlmv1_response.

  DATA: lv_hash TYPE zcl_md4=>ty_byte16,
        lv_rd1  TYPE x LENGTH 7,
        lv_rd2  TYPE x LENGTH 7,
        lv_rd3  TYPE x LENGTH 7,
        lv_r1   TYPE x LENGTH 8,
        lv_r2   TYPE x LENGTH 8,
        lv_r3   TYPE x LENGTH 8.


  lv_hash = zcl_md4=>hash( iv_encoding = '4103'
                           iv_string   = iv_password ).

  lv_rd1 = lv_hash.
  lv_rd2 = lv_hash+7.
  lv_rd3 = lv_hash+14.

  lv_r1 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd1 )
      iv_plaintext = iv_challenge ).
  lv_r2 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd2 )
      iv_plaintext = iv_challenge ).
  lv_r3 = zcl_des=>encrypt(
      iv_key       = zcl_des=>parity_adjust( lv_rd3 )
      iv_plaintext = iv_challenge ).

  CONCATENATE lv_r1 lv_r2 lv_r3 INTO rv_response IN BYTE MODE.

ENDMETHOD.


METHOD ntlmv2_hash.

  DATA: lv_xpass   TYPE xstring,
        lv_xtarget TYPE xstring,
        lv_data    TYPE xstring,
        lv_key     TYPE xstring.


  lv_key = zcl_md4=>hash( iv_encoding = '4103'
                          iv_string   = iv_password ).

  lv_xpass = lcl_convert=>codepage_4103( to_upper( iv_username ) ).
  lv_xtarget = lcl_convert=>codepage_4103( iv_target ) .
  CONCATENATE lv_xpass lv_xtarget INTO lv_data IN BYTE MODE.

  rv_hash = lcl_util=>hmac_md5( iv_key  = lv_key
                                iv_data = lv_data ).

ENDMETHOD.


METHOD ntlmv2_response.

  CONSTANTS: lc_signature TYPE xstring VALUE '01010000',
             lc_zero      TYPE xstring VALUE '00000000'.

  DATA: lv_data    TYPE xstring,
        lv_hmac    TYPE xstring,
        lv_time    TYPE ty_byte8,
        lv_blob    TYPE xstring,
        lv_v2hash  TYPE ty_byte16.


  lv_v2hash = ntlmv2_hash( iv_password = iv_password
                           iv_username = iv_username
                           iv_target   = iv_target ).

  IF iv_time IS INITIAL.
    lv_time = lcl_util=>since_epoc_hex( ).
  ELSE.
    lv_time = iv_time.
  ENDIF.

  CONCATENATE lc_signature lc_zero lv_time
    iv_nonce lc_zero iv_info lc_zero
    INTO lv_blob IN BYTE MODE.
  CONCATENATE iv_challenge lv_blob
    INTO lv_data IN BYTE MODE.

  lv_hmac = lcl_util=>hmac_md5( iv_key  = lv_v2hash
                                iv_data = lv_data ).

  CONCATENATE lv_hmac lv_blob INTO rv_response IN BYTE MODE.

ENDMETHOD.


METHOD session_key.

  DATA: lv_key TYPE xstring.


  lv_key = zcl_md4=>hash( iv_encoding = '4103'
                          iv_string   = iv_password ).

  lv_key = zcl_md4=>hash_hex( lv_key ).

  rv_session_key = zcl_arc4=>encrypt_hex(
      iv_key       =  lv_key
      iv_plaintext = '55555555555555555555555555555555' ). " todo

ENDMETHOD.


METHOD type_1_decode.

  DATA: lo_reader TYPE REF TO lcl_reader.


  CREATE OBJECT lo_reader
    EXPORTING
      iv_value = iv_msg
      iv_type  = c_message_type_1.

  rs_data-flags = lo_reader->flags( ).

* domain/target name
  IF rs_data-flags-negotiate_oem_domain_supplied = abap_true.
    rs_data-target_name = lo_reader->data_str( abap_true ).
  ELSE.
    rs_data-target_name = lo_reader->data_str( abap_false ).
  ENDIF.

* workstation fields
  IF rs_data-flags-negotiate_oem_workstation_sup = abap_true.
    rs_data-workstation = lo_reader->data_str( abap_true ).
  ELSE.
    rs_data-workstation = lo_reader->data_str( abap_false ).
  ENDIF.

* version
  IF rs_data-flags-negotiate_version = abap_true.
    rs_data-version = lo_reader->raw( 8 ).
  ENDIF.

ENDMETHOD.


METHOD type_1_encode.

  DATA: lo_writer TYPE REF TO lcl_writer.


  CREATE OBJECT lo_writer
    EXPORTING
      iv_type = c_message_type_1.

  lo_writer->flags( is_data-flags ).

* domain/target name
  IF is_data-flags-negotiate_oem_domain_supplied = abap_true.
    lo_writer->data_str( iv_oem  = abap_true
                         iv_data = is_data-target_name ).
  ELSE.
    lo_writer->data_str( is_data-target_name ).
  ENDIF.

* workstation fields
  IF is_data-flags-negotiate_oem_workstation_sup = abap_true.
    lo_writer->data_str( iv_oem  = abap_true
                         iv_data = is_data-workstation ).
  ELSE.
    lo_writer->data_str( is_data-workstation ).
  ENDIF.

  IF is_data-flags-negotiate_version = abap_true.
    lo_writer->raw( is_data-version ).
  ENDIF.

  rv_msg = lo_writer->message( ).

ENDMETHOD.


METHOD type_2_decode.

  DATA: lo_reader TYPE REF TO lcl_reader.


  CREATE OBJECT lo_reader
    EXPORTING
      iv_value = iv_msg
      iv_type  = c_message_type_2.

* target name
  rs_data-target_name = lo_reader->data_str( iv_oem ).

* flags
  rs_data-flags = lo_reader->flags( ).

* challenge
  rs_data-challenge = lo_reader->raw( 8 ).

* reserved
  lo_reader->skip( 8 ).

* target info
  rs_data-target_info = lo_reader->data_raw( ).

ENDMETHOD.


METHOD type_2_encode.

  DATA: lo_writer TYPE REF TO lcl_writer.


  CREATE OBJECT lo_writer
    EXPORTING
      iv_type = c_message_type_2.

* todo

  rv_msg = lo_writer->message( ).

ENDMETHOD.


METHOD type_3_build.

  DATA: lv_nonce TYPE ty_byte8.


  lv_nonce = lcl_util=>random_nonce( ).

*  IF is_data2-flags-negotiate_extended_session_sec = abap_true.
** Negotiate NTLM2 Key
*    ntlm2_session_response(
*      EXPORTING
*        iv_nonce         = lv_nonce
*        iv_challenge     = is_data2-challenge
*        iv_password      = iv_password
*      IMPORTING
*        ev_lm_response   = rs_data3-lm_resp
*        ev_ntlm_response = rs_data3-ntlm_resp ).
*  ELSE.
*    rs_data3-lm_resp = lmv1_response( iv_password  = iv_password
*                                      iv_challenge = is_data2-challenge ).
*
*    rs_data3-ntlm_resp = ntlmv1_response( iv_password  = iv_password
*                                          iv_challenge = is_data2-challenge ).

  rs_data3-lm_resp = lmv2_response( iv_password  = iv_password
                                    iv_domain    = iv_domain
                                    iv_username  = iv_username
                                    iv_nonce     = lv_nonce
                                    iv_challenge = is_data2-challenge ).

  rs_data3-ntlm_resp = ntlmv2_response( iv_password  = iv_password
                                        iv_username  = iv_username
                                        iv_target    = iv_domain
                                        iv_info      = is_data2-target_info
                                        iv_nonce     = lv_nonce
                                        iv_challenge = is_data2-challenge ).

*  ENDIF.

  rs_data3-target_name = iv_domain.
  rs_data3-user_name   = iv_username.
  rs_data3-workstation = iv_workstation.

*  IF is_data2-flags-negotiate_key_exch = abap_true.
*    rs_data3-session_key = session_key( iv_password ).
*  ENDIF.

*  rs_data3-flags = is_data2-flags.
  rs_data3-flags-r3 = abap_true.
  rs_data3-flags-negotiate_extended_session_sec = abap_true.
  rs_data3-flags-negotiate_ntlm = abap_true.
  rs_data3-flags-negotiate_seal = abap_true.
  rs_data3-flags-negotiate_sign = abap_true.
  rs_data3-flags-request_target = abap_true.
  rs_data3-flags-negotiate_unicode = abap_true.

ENDMETHOD.


METHOD type_3_decode.

  DATA: lo_reader TYPE REF TO lcl_reader.


  CREATE OBJECT lo_reader
    EXPORTING
      iv_value = iv_msg
      iv_type  = c_message_type_3.

* LM challenge response
  rs_data-lm_resp = lo_reader->data_raw( ).

* NTLM challenge response
  rs_data-ntlm_resp = lo_reader->data_raw( ).

* domain/target name
  rs_data-target_name = lo_reader->data_str( iv_oem ).

* user name
  rs_data-user_name = lo_reader->data_str( iv_oem ).

* workstation name
  rs_data-workstation = lo_reader->data_str( iv_oem ).

* encrypted random session key
  rs_data-session_key = lo_reader->data_raw( ).

* negotiate flags
  rs_data-flags = lo_reader->flags( ).

* version
  IF rs_data-flags-negotiate_version = abap_true.
    rs_data-version = lo_reader->raw( 8 ).
  ENDIF.

ENDMETHOD.


METHOD type_3_encode.

  DATA: lo_writer TYPE REF TO lcl_writer.


  CREATE OBJECT lo_writer
    EXPORTING
      iv_type = c_message_type_3.

* LM challenge response
  lo_writer->data_raw( is_data-lm_resp ).

* NTLM challenge response
  lo_writer->data_raw( is_data-ntlm_resp ).

* domain/target name
  lo_writer->data_str( is_data-target_name ).

* user name
  lo_writer->data_str( is_data-user_name ).

* workstation name
  lo_writer->data_str( is_data-workstation ).

* encrypted random session key
  lo_writer->data_raw( is_data-session_key ).

* negotiate flags
  lo_writer->flags( is_data-flags ).

* version
  IF is_data-flags-negotiate_version = abap_true.
    lo_writer->raw( is_data-version ).
  ENDIF.

* MIC?
* todo

  rv_msg = lo_writer->message( ).

ENDMETHOD.
ENDCLASS.