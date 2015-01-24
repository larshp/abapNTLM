class ZCL_NTLM definition
  public
  final
  create public .

public section.
*"* public components of class ZCL_NTLM
*"* do not include other source files here!!!

  constants C_SIGNATURE type XSTRING value '4E544C4D53535000'. "#EC NOTEXT

  class-methods GET
    importing
      !IV_USERNAME type STRING
      !IV_PASSWORD type STRING
      !IV_DOMAIN type STRING
      !IV_URL type STRING
    returning
      value(RV_RESULT) type XSTRING .
protected section.
*"* protected components of class ZCL_NTLM
*"* do not include other source files here!!!

  types:
    TY_BYTE8 type x length 8 .
  types:
    TY_BYTE24 type x length 24 .

  constants C_MESSAGE_TYPE_1 type XSTRING value '01000000'. "#EC NOTEXT
  constants C_MESSAGE_TYPE_2 type XSTRING value '02000000'. "#EC NOTEXT
  constants C_MESSAGE_TYPE_3 type XSTRING value '03000000'. "#EC NOTEXT

  class-methods LM_RESPONSE .
  class-methods NTLMV2_RESPONSE
    importing
      !IV_PASSWORD type STRING
      !IV_USERNAME type STRING
      !IV_TARGET type STRING
      !IV_CHALLENGE type TY_BYTE8
      !IV_INFO type XSTRING
    returning
      value(RV_RESPONSE) type XSTRING
    raising
      CX_STATIC_CHECK .
  class-methods NTLM_RESPONSE
    importing
      !IV_PASSWORD type STRING
      !IV_CHALLENGE type TY_BYTE8
    returning
      value(RV_RESPONSE) type TY_BYTE24 .
  class-methods TYPE_1_DECODE
    importing
      !IV_VALUE type STRING .
  class-methods TYPE_2_ENCODE
    returning
      value(RV_VALUE) type STRING .
  class-methods TYPE_3_DECODE
    importing
      !IV_VALUE type STRING .
  class-methods TYPE_1_ENCODE
    returning
      value(RV_VALUE) type STRING .
  class-methods TYPE_2_DECODE
    importing
      !IV_VALUE type STRING
    returning
      value(RV_CHALLENGE) type XSTRING .
  class-methods TYPE_3_ENCODE
    returning
      value(RV_VALUE) type STRING .
private section.
*"* private components of class ZCL_NTLM
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_NTLM IMPLEMENTATION.


METHOD get.

* http://davenport.sourceforge.net/ntlm.html
* http://blogs.msdn.com/b/chiranth/archive/2013/09/21/ntlm-want-to-know-how-it-works.aspx
* http://www.innovation.ch/personal/ronald/ntlm.html

* todo, endianness? detect via signature?

  DATA: li_client TYPE REF TO if_http_client,
        lv_value  TYPE string,
        lt_fields TYPE tihttpnvp.

  FIELD-SYMBOLS: <ls_field> LIKE LINE OF lt_fields.


  cl_http_client=>create_by_url(
    EXPORTING
      url    = iv_url
      ssl_id = 'ANONYM' " todo, as optional input?
    IMPORTING
      client = li_client ).

  li_client->propertytype_logon_popup = li_client->co_disabled.

  li_client->send( ).
  li_client->receive(
    EXCEPTIONS
      http_communication_failure = 1
      http_invalid_state         = 2
      http_processing_failed     = 3
      OTHERS                     = 4 ).
  IF sy-subrc <> 0.
* todo
    BREAK-POINT.
  ENDIF.

  li_client->response->get_header_fields( CHANGING fields = lt_fields ).

  READ TABLE lt_fields ASSIGNING <ls_field>
    WITH KEY name = 'www-authenticate' value = 'NTLM'.      "#EC NOTEXT
  IF sy-subrc <> 0.
* no NTML destination
    BREAK-POINT.
  ENDIF.

***********************************************

  lv_value = type_1_encode( ).
  CONCATENATE 'NTLM' lv_value INTO lv_value SEPARATED BY space.
  li_client->request->set_header_field(
      name  = 'authorization'
      value = lv_value ).                                   "#EC NOTEXT

  li_client->send( ).
  li_client->receive(
    EXCEPTIONS
      http_communication_failure = 1
      http_invalid_state         = 2
      http_processing_failed     = 3
      OTHERS                     = 4 ).
  IF sy-subrc <> 0.
* todo
  ENDIF.

  li_client->response->get_header_fields( CHANGING fields = lt_fields ).

  READ TABLE lt_fields ASSIGNING <ls_field>
    WITH KEY name = 'www-authenticate'.                     "#EC NOTEXT
  IF sy-subrc <> 0.
* no NTML destination
    BREAK-POINT.
  ENDIF.

  lv_value = <ls_field>-value+5.
  type_2_decode( lv_value ).

* todo

  li_client->close( ).

ENDMETHOD.


METHOD lm_response.

* todo
  RETURN.

ENDMETHOD.


METHOD ntlmv2_response.

  CONSTANTS: lc_signature TYPE xstring VALUE '01010000',
             lc_zero      TYPE xstring VALUE '00000000'.

  DATA: lv_xpass   TYPE xstring,
        lv_xtarget TYPE xstring,
        lv_data    TYPE xstring,
        lv_hmac    TYPE xstring,
        lv_random  TYPE xstring,
        lv_time    TYPE xstring,
        lv_blob    TYPE xstring,
        lv_v2hash  TYPE xstring,
        lv_key     TYPE xstring.


  lv_key = zcl_md4=>hash( iv_encoding = '4103'
                          iv_string   = iv_password ).

  lv_xpass = lcl_convert=>codepage_4103( to_upper( iv_username ) ).
  lv_xtarget = lcl_convert=>codepage_4103( iv_target ) .
  CONCATENATE lv_xpass lv_xtarget INTO lv_data IN BYTE MODE.

  lv_v2hash = lcl_util=>hmac_md5( iv_key  = lv_key
                                  iv_data = lv_data ).

*  lv_time = '0090D336B734C301'.
  lv_time = lcl_util=>since_epoc_hex( ).
  lv_random = lcl_util=>random_nonce( ).

  CONCATENATE lc_signature lc_zero lv_time
    lv_random lc_zero iv_info lc_zero
    INTO lv_blob IN BYTE MODE.
  CONCATENATE iv_challenge lv_blob
    INTO lv_data IN BYTE MODE.

  lv_hmac = lcl_util=>hmac_md5( iv_key  = lv_v2hash
                                iv_data = lv_data ).

  CONCATENATE lv_hmac lv_blob INTO rv_response IN BYTE MODE.

ENDMETHOD.


METHOD ntlm_response.

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


METHOD type_1_decode.

  DATA: lv_xstr  TYPE xstring,
        ls_target_name TYPE ty_fields,
        ls_workst_name TYPE ty_fields,
        ls_flags TYPE ty_flags.


  lcl_read=>signature( EXPORTING iv_value = iv_value
                                 iv_type = C_MESSAGE_TYPE_1
                       CHANGING  cv_xstr = lv_xstr ) .

  lcl_read=>flags( IMPORTING es_flags = ls_flags
                   CHANGING cv_xstr = lv_xstr ).

* domain/target name
  lcl_read=>fields( IMPORTING es_fields = ls_target_name
                    CHANGING cv_xstr = lv_xstr ).

* workstation fields
  lcl_read=>fields( IMPORTING es_fields = ls_workst_name
                    CHANGING cv_xstr = lv_xstr ).

* payload
* todo

* todo
  BREAK-POINT.

ENDMETHOD.


METHOD type_1_encode.

  DATA: lv_xstr  TYPE xstring,
        ls_flags TYPE ty_flags.


  lv_xstr = lcl_write=>signature( c_message_type_1 ).

* minimal flags, Negotiate NTLM and Negotiate OEM
  ls_flags-negotiate_ntlm = abap_true.
  ls_flags-negotiate_oem = abap_true.

  lcl_write=>flags( EXPORTING is_flags = ls_flags
                    CHANGING  cv_xstr = lv_xstr ).

  rv_value = lcl_convert=>base64_encode( lv_xstr ).

ENDMETHOD.


METHOD type_2_decode.

  DATA: ls_target_name TYPE ty_fields,
        ls_target_info TYPE ty_fields,
        ls_flags TYPE ty_flags,
        lv_xstr  TYPE xstring.


  lcl_read=>signature( EXPORTING iv_value = iv_value
                                 iv_type = C_MESSAGE_TYPE_2
                       CHANGING  cv_xstr = lv_xstr ) .

* target name
  lcl_read=>fields( IMPORTING es_fields = ls_target_name
                    CHANGING cv_xstr = lv_xstr ).

* flags
  lcl_read=>flags( IMPORTING es_flags = ls_flags
                   CHANGING cv_xstr = lv_xstr ).

* challenge
  rv_challenge = lv_xstr(8).
  lv_xstr = lv_xstr+8.

* reserved
  lv_xstr = lv_xstr+8.

* target info
  lcl_read=>fields( IMPORTING es_fields = ls_target_info
                    CHANGING cv_xstr = lv_xstr ).

  BREAK-POINT.

ENDMETHOD.


METHOD type_2_encode.

  DATA: lv_xstr TYPE xstring.


  lv_xstr = lcl_write=>signature( c_message_type_2 ).

* todo

ENDMETHOD.


METHOD type_3_decode.

  DATA: lv_xstr        TYPE xstring,
        ls_lm_resp     TYPE ty_fields,
        ls_ntlm_resp   TYPE ty_fields,
        ls_target_name TYPE ty_fields,
        ls_user_name   TYPE ty_fields,
        ls_workst_name TYPE ty_fields,
        ls_session_key TYPE ty_fields,
        ls_flags       TYPE ty_flags.


  lcl_read=>signature( EXPORTING iv_value = iv_value
                                 iv_type = C_MESSAGE_TYPE_3
                       CHANGING  cv_xstr = lv_xstr ) .

* LM challenge response
  lcl_read=>fields( IMPORTING es_fields = ls_lm_resp
                    CHANGING cv_xstr = lv_xstr ).

* NTLM challenge response
  lcl_read=>fields( IMPORTING es_fields = ls_ntlm_resp
                    CHANGING cv_xstr = lv_xstr ).

* domain/target name
  lcl_read=>fields( IMPORTING es_fields = ls_target_name
                    CHANGING cv_xstr = lv_xstr ).

* user name
  lcl_read=>fields( IMPORTING es_fields = ls_user_name
                    CHANGING cv_xstr = lv_xstr ).

* workstation name
  lcl_read=>fields( IMPORTING es_fields = ls_workst_name
                    CHANGING cv_xstr = lv_xstr ).

* encrypted random session key
  lcl_read=>fields( IMPORTING es_fields = ls_session_key
                    CHANGING cv_xstr = lv_xstr ).

* negotiate flags
  lcl_read=>flags( IMPORTING es_flags = ls_flags
                   CHANGING cv_xstr = lv_xstr ).

* todo

  BREAK-POINT.

ENDMETHOD.


METHOD type_3_encode.

  DATA: lv_xstr        TYPE xstring,
        ls_lm_resp     TYPE ty_fields,
        ls_ntlm_resp   TYPE ty_fields,
        ls_target_name TYPE ty_fields,
        ls_user_name   TYPE ty_fields,
        ls_workst_name TYPE ty_fields,
        ls_session_key TYPE ty_fields,
        ls_flags       TYPE ty_flags.


  lv_xstr = lcl_write=>signature( c_message_type_2 ).

* LM challenge response
  lcl_write=>fields( EXPORTING is_fields = ls_lm_resp
                     CHANGING  cv_xstr = lv_xstr ).

* NTLM challenge response
  lcl_write=>fields( EXPORTING is_fields = ls_ntlm_resp
                     CHANGING  cv_xstr = lv_xstr ).

* domain/target name
  lcl_write=>fields( EXPORTING is_fields = ls_target_name
                     CHANGING  cv_xstr = lv_xstr ).

* user name
  lcl_write=>fields( EXPORTING is_fields = ls_user_name
                     CHANGING  cv_xstr = lv_xstr ).

* workstation name
  lcl_write=>fields( EXPORTING is_fields = ls_workst_name
                     CHANGING  cv_xstr = lv_xstr ).

* encrypted random session key
  lcl_write=>fields( EXPORTING is_fields = ls_session_key
                     CHANGING  cv_xstr = lv_xstr ).

* negotiate flags
  lcl_write=>flags( EXPORTING is_flags = ls_flags
                    CHANGING  cv_xstr = lv_xstr ).

* MIC?
* todo

* Payload
* todo

  rv_value = lcl_convert=>base64_encode( lv_xstr ).

ENDMETHOD.
ENDCLASS.