REPORT zntlm_test.

PARAMETERS: p_url    TYPE text100,
            p_user   TYPE text20,
            p_passw  TYPE text20,
            p_domain TYPE text20.

INITIALIZATION.
  PERFORM initialization.

START-OF-SELECTION.
  PERFORM run.

*&---------------------------------------------------------------------*
*&      Form  run
*&---------------------------------------------------------------------*
*       text
*----------------------------------------------------------------------*
FORM run.

  zcl_ntlm=>get(
      iv_username = p_user
      iv_password = p_passw
      iv_domain   = p_domain
      iv_url      = p_url ).

* todo

ENDFORM.                    "run

*&---------------------------------------------------------------------*
*&      Form  initialization
*&---------------------------------------------------------------------*
*       text
*----------------------------------------------------------------------*
FORM initialization.

  CALL FUNCTION 'RS_SUPPORT_SELECTIONS'
    EXPORTING
      report               = sy-cprog
      variant              = 'DEFAULT'
    EXCEPTIONS
      variant_not_existent = 01
      variant_obsolete     = 02.

ENDFORM.                    "initialization