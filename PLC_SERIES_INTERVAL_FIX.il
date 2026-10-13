; Insert BEFORE Presets_Normal in SIREN_CONTROL
; Network: Series_Interval_Positive
LDN %M0
AND [ %MW6 >= 0 ]
[ %MW13 := %MW6 / 1000 ]

; Network: Series_Interval_Unsigned
LDN %M0
AND [ %MW6 < 0 ]
[ %MW13 := %MW6 + 32536 ]
[ %MW13 := %MW13 / 1000 ]
[ %MW13 := %MW13 + 33 ]

; Remove the old division from Presets_Normal.
; Keep: [ %TM3.P := %MW13 ]
