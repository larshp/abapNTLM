class ZCL_NTLM definition
  public
  final
  create public .

public section.
*"* public components of class ZCL_NTLM
*"* do not include other source files here!!!

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
    BEGIN OF ty_flags,
           negotiate_56 TYPE abap_bool,
           negotiate_key_exch TYPE abap_bool,
           negotiate_128 TYPE abap_bool,
           r1 TYPE abap_bool,
           r2 TYPE abap_bool,
           r3 TYPE abap_bool,
           negotiate_version TYPE abap_bool,
           r4 type abap_bool,
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
    ty_byte4 TYPE x LENGTH 4 .

  class-methods BASE64_DECODE
    importing
      !IV_STRING type STRING
    returning
      value(RV_XSTRING) type XSTRING .
  class-methods BASE64_ENCODE
    importing
      !IV_XSTRING type XSTRING
    returning
      value(RV_STRING) type STRING .
  class-methods FLAGS_DECODE
    importing
      !IV_HEX type TY_BYTE4
    returning
      value(RS_FLAGS) type TY_FLAGS .
  class-methods FLAGS_ENCODE
    importing
      !IS_FLAGS type TY_FLAGS
    returning
      value(RV_HEX) type TY_BYTE4 .
  class-methods TYPE_1
    returning
      value(RV_STRING) type STRING .
  class-methods TYPE_2
    importing
      !IV_VALUE type STRING .
  class-methods TYPE_3
    returning
      value(RV_STRING) type STRING .
private section.
*"* private components of class ZCL_NTLM
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_NTLM IMPLEMENTATION.


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

ENDMETHOD.


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

ENDMETHOD.


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

ENDMETHOD.


METHOD flags_encode.

* todo

ENDMETHOD.


METHOD get.

* http://davenport.sourceforge.net/ntlm.html
* http://blogs.msdn.com/b/chiranth/archive/2013/09/21/ntlm-want-to-know-how-it-works.aspx
* http://www.innovation.ch/personal/ronald/ntlm.html

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
  ENDIF.

  li_client->response->get_header_fields( CHANGING fields = lt_fields ).

  READ TABLE lt_fields ASSIGNING <ls_field>
    WITH KEY name = 'www-authenticate' value = 'NTLM'.      "#EC NOTEXT
  IF sy-subrc <> 0.
* no NTML destination
    BREAK-POINT.
  ENDIF.

***********************************************

  lv_value = type_1( ).
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

  li_client->response->get_header_fields( CHANGING fields = lt_fields ).

  READ TABLE lt_fields ASSIGNING <ls_field>
    WITH KEY name = 'www-authenticate'.                     "#EC NOTEXT
  IF sy-subrc <> 0.
* no NTML destination
    BREAK-POINT.
  ENDIF.

  type_2( <ls_field>-value ).

* todo

  li_client->close( ).

ENDMETHOD.


METHOD type_1.

* NEGOTIATE_MESSAGE

  DATA: lv_xstring TYPE xstring,
        lv_flags   TYPE xstring,
        lv_type    TYPE xstring.


* signature, NTLMSSP\0
  lv_xstring = '4E544C4D53535000'.

  lv_type = '01000000'.
  CONCATENATE lv_xstring lv_type INTO lv_xstring IN BYTE MODE.

* minimal flags, Negotiate NTLM and Negotiate OEM
  lv_flags = '02020000'.
  CONCATENATE lv_xstring lv_flags INTO lv_xstring IN BYTE MODE.

  rv_string = base64_encode( lv_xstring ).

ENDMETHOD.


METHOD type_2.

* CHALLENGE_MESSAGE

  DATA: lv_str  TYPE string,
        lv_target_name TYPE xstring,
        lv_target_info TYPE xstring,
        lv_challenge TYPE xstring,
        lv_flags TYPE xstring,
        lv_xstr TYPE xstring.


  IF strlen( iv_value ) < 5 OR iv_value(4) <> 'NTLM'.
    BREAK-POINT.
  ENDIF.

  lv_str = iv_value+5.
  lv_xstr = base64_decode( lv_str ).

* signature
  IF xstrlen( lv_xstr ) < 8 OR lv_xstr(8) <> '4E544C4D53535000'.
    BREAK-POINT.
  ENDIF.
  lv_xstr = lv_xstr+8.

* message type
  IF xstrlen( lv_xstr ) < 4 OR lv_xstr(4) <> '02000000'.
    BREAK-POINT.
  ENDIF.
  lv_xstr = lv_xstr+4.

* target name
  lv_target_name = lv_xstr(8).
  lv_xstr = lv_xstr+8.

* flags
  lv_flags = lv_xstr(4).
  lv_xstr = lv_xstr+4.

* challenge
  lv_challenge = lv_xstr(8).
  lv_xstr = lv_xstr+8.

* reserved
  lv_xstr = lv_xstr+8.

* target info
  lv_target_info = lv_xstr(8).
  lv_xstr = lv_xstr+8.

  BREAK-POINT.

ENDMETHOD.


METHOD type_3.

* AUTHENTICATE_MESSAGE

  DATA: lv_xstring TYPE xstring,
        lv_type    TYPE xstring.


* signature, NTLMSSP\0
  lv_xstring = '4E544C4D53535000'.

* type
  lv_type = '03000000'.
  CONCATENATE lv_xstring lv_type INTO lv_xstring IN BYTE MODE.

* LM
* todo

* NTLM

* target name

* user name

* workstation name


  rv_string = base64_encode( lv_xstring ).

ENDMETHOD.
ENDCLASS.