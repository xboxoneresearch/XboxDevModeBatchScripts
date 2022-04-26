:: Stops then deletes the four primary telemetry services on Xbox SystemOS. Requires Admin or above.
sc stop etwuploaderservice
sc stop DiagTrack
sc stop XBBlackbox
sc stop xbdiagservice
sc delete etwuploaderservice
sc delete DiagTrack
sc delete XBBlackbox
sc delete xbdiagservice