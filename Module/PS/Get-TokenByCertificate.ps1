Function Get-TokenByCertificate
{
	<#
	.SYNOPSIS
		Get OAuth access token using client certificate.

	.EXAMPLE
		#Params
		$Certificate = Get-PfxCertificate -FilePath ./Certificate.pfx
		$TenantId = "12345678-1234-1234-1234-1234567890ab"
		$ApplicationId = "12345678-1234-1234-1234-1234567890ab"
		$Scope = "https://graph.microsoft.com/.default"

		#Token
		$AccessToken = Get-TokenByCertificate -Certificate $Certificate -TenantId $TenantId -ApplicationId $ApplicationId -Scope $Scope
		$AccessToken

	.NOTES
		Author: Michal Gajda

	.LINK
		https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory = $true)][String]$TenantId,
		[Parameter(Mandatory = $true)][String]$ApplicationId,
		[Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
		[Parameter()][String]$Scope = "https://graph.microsoft.com/.default"
	)

	#JWT params
	$CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

	$JWT_exp = [math]::Floor(((Get-Date) - ([datetime]::Parse("1970-01-01T00:00:00Z"))).TotalSeconds)
	$JWT_nbf = $JWT_exp + (10 * 60)

	#JWTHeader
	$JWTHeader = @{
		alg = "RS256"
		typ = "JWT"
		x5t = "$($CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '=')"
	} | ConvertTo-Json -Compress

	#JWTClaims
	$JWTClaims = @{
		aud = "https://login.microsoftonline.com/$TenantId/oauth2/token"
		exp = $JWT_exp
		iss = "$ApplicationId"
		jti = ([guid]::NewGuid()).Guid
		nbf = $JWT_nbf
		sub = "$ApplicationId"
	}  | ConvertTo-Json -Compress

	$StringList = @($JWTHeader, $JWTClaims)

	#JWT encoding
	$EncodedStringList = @()
	$StringList | ForEach-Object {
		$ClearTextString = $_
		# Convert supplied strings to base64
		$ClearTextBytes = [System.Text.Encoding]::UTF8.GetBytes($ClearTextString)
		$Base64EncodedString = [System.Convert]::ToBase64String($ClearTextBytes).Replace('=', '').Replace('+', '-').Replace('/', '_')
		$EncodedStringList += $Base64EncodedString
	}

	# Join header and Payload with "." to create a valid (unsigned) JWT
	$StringToSign = $EncodedStringList -join '.'

	# Get the private key object of your certificate
	$PrivateKey = $Certificate.PrivateKey

	# Define RSA signature and hashing algorithm
	$RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
	$HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

	# Create a signature of the JWT
	$Signature = [System.Convert]::ToBase64String($PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($StringToSign),$HashAlgorithm,$RSAPadding)).Replace('=', '').Replace('+', '-').Replace('/', '_')

	# Join the signature to the JWT with "."
	$JWT = $StringToSign + "." + $Signature

	# Headers for the request with JWT as Authorization
	$Headers = @{ Authorization = "Bearer $JWT" }

	# Create a hash with body parameters
	$Body = @{
		client_id = $ApplicationId
		client_assertion = $JWT
		client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		scope = $Scope
		grant_type = "client_credentials"
	}

	# Token endpoint for the request
	$Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

	# Build the token request
	$RequestParams = @{
		ContentType = 'application/x-www-form-urlencoded'
		Method = 'POST'
		Body = $Body
		Uri = $Uri
		Headers = $Headers
	}

	# Get the token
	$Response = Invoke-RestMethod @RequestParams

	Return $Response.access_token
}

# SIG # Begin signature block
# MIIixQYJKoZIhvcNAQcCoIIitjCCIrICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBJdhZ+S+xaap0B
# iC88539Lg6cekucRYyReTv9FzIBvI6CCHDUwggQuMIICFqADAgECAhBTXA6VE4ZJ
# kkZJJNYxZDR4MA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNVBAMMD01pY2hhbCBHYWpk
# YSBDQTAeFw0yNjExMDkxMDI2MTZaFw0yNzExMDkxMDM2MTZaMCMxITAfBgNVBAMM
# GE1pY2hhbCBHYWpkYSBDb2RlU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBAMbcpWN3ctQ7jeDfNLFP+cxh3Wd9vA1r6jN9iQYAS15j1wEI6V53
# yWjJoYJKmeIQtXxQYWhsfPE5cJ2CHTTxhsovsKp2zm/30MRL50maZrbwdkZ/KZyc
# LLPk+dyNvfWfH5UBQV0pRCLN1ILXPQd1F3LqsBPH7cko5L5Om+b3oBl2w9CxF4G/
# UbTFh/9qgcAYXvOPNDzUFFryFepSiwAAfC6D5RHaFMWljb+gegRUkl+/B4g8Xf3R
# mbFcl2lTqhRENPFhOdrtngy9ldkz/tyUO3Reaixhy+EA8/bTOtK5Mq7RtyAA2dhZ
# IH5AQrN5U9jIY8SL+rizT4JvF/L6TQgqRC0CAwEAAaNnMGUwDgYDVR0PAQH/BAQD
# AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFGfJIhIP6r4+OzlU
# V5fnBSoEZF3BMB0GA1UdDgQWBBRuO6w3QLbfSM2OJPzXgPrB6kf7zTANBgkqhkiG
# 9w0BAQsFAAOCAgEAT752PsmY9UcAejy9a4CgH74wvHt5otpbyMGtM0qUqlyc+8q/
# E69LBVDjPt6CEXiJFMTRNXoVTKkEjZA0wO4GsyBg+T9ODbGxl/Vn+39qsqLh0HYZ
# aTQyPGfsVtm/ZuvcwJYnm2gdHUjb3T9joP+vGe+2bFfzRnCIAjdM66Bgq6pxSPlt
# KQLmLsWyygMqTHaam4VLe5Kaqf8DgibsJ6NWHhS4/b7XdZaajp6YpFaoIARAoGZe
# hOVgZaDIIi9yEFfhxhAhX5G9+yJEVjJH/ZnRCY3vRHvFYQHtvJcxQrUmG16IeA3L
# 6t2+UzT6mWKIrFUprO3XceGZeT/sKn7vUqSnKU0fJR/C9+CLjNaD2P4U5QXgIa0+
# bN+RGuB+0u4NUj0fOTFQRKAxIhgzlzUJbMUceDOhmg8aMgG9vrI6Ukhp0q4iNjvg
# 7HLDM+mDzbthNy+duIAKli3DTfGMKvpy1PLfY9NlTQLi2suhppUlzMMxtBuQCajq
# dZBYLEQIBZyrsnfG7dleDRzXHy6E137/EXx3MeYj2ZT0vGRwDH0qQWZkL3WLILN9
# t1hwlueP2imnQ8IyxxGRRgR61LpEoeVxpkMP/LlsXngLvxDuAZVFadHkcH4YvoZx
# bu8t/sbwZWIiVhZarLyochr1eXwecXNbjXucI7tGAxanRq0SFl7mQyJ6YEMwggTv
# MIIC16ADAgECAhASiMPAZpZmrkW5VhWUwZQNMA0GCSqGSIb3DQEBCwUAMBoxGDAW
# BgNVBAMMD01pY2hhbCBHYWpkYSBDQTAeFw0yNjExMDkxMDI1MjNaFw0zNjExMDkx
# MDM1MjFaMBoxGDAWBgNVBAMMD01pY2hhbCBHYWpkYSBDQTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAKoTH4NpYpZwRaNHiIVPS/34t3cwY7fAjDjtY08F
# Vs0af5/C6EY7OwwmrIf6f8bMHOPI25lfZ57mOaTdFpZKK1/6y56KKc8vhYMmUYeB
# 3KGZ+NYGdDsyLt+PFG32nGwpDVu8r/iKJMk5tWwAbTpyIa+DD/W+skB3jNf93aCh
# A8htMXwHooHMkNZ7p5E5fx8NQjY/mlTtGB7IZ61DBwg4Zm74avD+56RgbkvTz222
# V6vKQxU30F4wu6fmrRVzLDbZw1tCMND389QRx01MuD9lCzsZcty4dj4oWh4PoJKf
# HtoHuoUFtJW9UOLsNxryat6JFlbkggPb6CbWvwJfCsCXgjEFP1DEtO5KFjup3ME9
# a+Duvsk3XkbXfNWeVdDZ12LqHu89QV1z6pAi/qAf21zYO/bNfwKoaN9sqlDEVEEM
# bytam3Iw1WxDgweWshAXTABOKOWHVryU9VFPhRTlazEXZZjGXup6kxk4+zpU9DAx
# BqGfZvRevGlVqmr6/1qt8FtQi73+L+WQu51lVAMezQNhTukCvA3odiCOg2/LHLXb
# 7Du3SVeQgM52OUAN6CP7dPHJUf5EBiWidiNqx2B1a9l+pxIeLPdn+7t64uQdY6j9
# NpOY7CNyZDcx/KwZ4IG++VQlOcMbHnDuooD2/lCFEPf8wX974KvQk5to90b1TYB1
# TVU1AgMBAAGjMTAvMA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQUZ8kiEg/qvj47
# OVRXl+cFKgRkXcEwDQYJKoZIhvcNAQELBQADggIBACbBQxFIE77wc05vEf2IjBLC
# plLr7Yo71AIg1JwggEze1ZWQcRrZqDqpH4i/hbihW4LlSDxJVQXCacnknJg0p2Ur
# maP/0fyI8KhYkmj+VQh1VFkovErPQp+aYSMD9sDsr7BqqmSLNMoL3HV7YZM9qlX+
# sR0is+Cg+cT0bq+SHxTBmb4EUy3lD6+gzH3qvv79fqMHA6JXBbNDVDYyaOFB2y51
# U+F1yzbf1NzVGkTdFv9JzO57WneJ3qLxFAfKckVBsn0f+nUsNkTP6c42hHlc1dna
# H4zgt0Ie8CIPg3mwy28hnG7C80C3T0B8bUBC2NntGMjxYm8mML2v7xZRhAwkBUx/
# GtklhGUGiHfBCKyy2YgSGWI7/OmOK4dv3+1Vi+3FKyFXwZ2FibmA12WaIXsaoz9N
# vIVIu+vqm01f6C3kFj/VxVjVa3Q6vSeq/Lk7y/HKCGFoQzbwUT70VKBC/X/oSI0k
# BRiMQMoHUwJhwehWszvwh6/Oul7We3618pGfjgSeaDjRhb1t7aOLs9WIt+n4HOUj
# Aiq5MJ/bLbVBxVSCzoMblRwX1XU5bpJedyN2rbXhLfDuywISBT0N6nd+cQ78RjbX
# QO99Vegf01cCG8vicJKWAHOK78a3sCUdgC1ZSIqpu2FhdYa5QdNn3eCAey1X8nnE
# veaEYam2B60G1P0WV02OMIIFyTCCBLGgAwIBAgIQG7WPJSrfIwBJKMmuPX7tJzAN
# BgkqhkiG9w0BAQwFADB+MQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBU
# ZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24g
# QXV0aG9yaXR5MSIwIAYDVQQDExlDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBMB4X
# DTIxMDUzMTA2NDMwNloXDTI5MDkxNzA2NDMwNlowgYAxCzAJBgNVBAYTAlBMMSIw
# IAYDVQQKExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0
# dW0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxJDAiBgNVBAMTG0NlcnR1bSBUcnVz
# dGVkIE5ldHdvcmsgQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL35ePjm1YAMZJ2GG5ZkZz8iOh51AX3v+1xnjMnMXGupkea5QuUgS5vam3u5mV3Z
# m4BL14RAKyfT6Lowuz4JGqdJle8rQCTCl8en7psl76gKAJeFWqqd3CnJ4jUH63BN
# StbBs1a4oUE4m9H7MX+P4F/hsT8PjhZJYNcGjRj5qiYQqyrT0NFnjRtGvkcw1S5y
# 0cVj2udjeUR+S2MkiYYuND8pTFKLKqfA4pEoibnAW/kd2ecnrf+aApfBxlCSmwIs
# vam5NFkKv4RK/9/+s5/r2Z7gmCPspmt3FirbzK07HKSH3EZzXhliaEVX5JCCQrtC
# 1vBh4MGjPWajXfQY7ojJjRdFKZkydQIx7ikmyGsC5rViRX83FVojaInUPt5OJ7Dw
# QAy8TRfLTaKzHtAGWt32k89XdZn1+oYaZ3izv5b+NNy951JW5bPldXvXQZEF3F1p
# 45UNQ7n8g5Y5lXtsgFpPE3LG130pekS6UqQq1UFGCSD+IqC2WzCNvIkM1ddw+IdS
# /drvrFEuB7NO/tAJ2nDvmPpW5m3btVdL3OUsJRXIni54TvjanJ6GLMpX8xrlyJKL
# GoKWesO8UBJp2A5aRos66yb6I8m2sIG+QgCk+Nb+MC7H0kb25Y51/fLMudCHW8wG
# EGC7gzW3XmfeR+yZSPGkoRX+rYxijjlVTzkWubFjnf+3AgMBAAGjggE+MIIBOjAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS2oVQ5AsOgP46KvPrU+Bym0ToO/TAf
# BgNVHSMEGDAWgBQIds3LB/8k9sXN7buQvOKEN0Z19zAOBgNVHQ8BAf8EBAMCAQYw
# LwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL2NybC5jZXJ0dW0ucGwvY3RuY2EuY3Js
# MGsGCCsGAQUFBwEBBF8wXTAoBggrBgEFBQcwAYYcaHR0cDovL3N1YmNhLm9jc3At
# Y2VydHVtLmNvbTAxBggrBgEFBQcwAoYlaHR0cDovL3JlcG9zaXRvcnkuY2VydHVt
# LnBsL2N0bmNhLmNlcjA5BgNVHSAEMjAwMC4GBFUdIAAwJjAkBggrBgEFBQcCARYY
# aHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3DQEBDAUAA4IBAQBRwqFY
# FiIQi/yGMdTCMtNc+EuiL2o+TfirCB7t1ej65wgN7LfGHg6ydQV6sQv613RqAAYf
# pM6q8mt92BHAEQjUDk1hxTqo+rHh45jq4mP9QfWTfQ28XZI7kZplutBfTL5MjWgD
# EBbV8dAEioUz+TfnWy4maUI8us281HrpTZ3a50P7Y1KAhQTEJZVV8H6nnwHFWyj4
# 4M6GcKYnOzn7OC6YU2UidS3X9t0iIpGW691o7T+jGZfTOyWI7DYSPal+zgKNBZqS
# pyduRbKcYoY3DaQzjteoTtBKF0NMxfGnbNIeWGwUUX6KVKH27595el2BmhaQD+G7
# 8UoA+fndvu2q7M4KMIIGgjCCBGqgAwIBAgIQKPB3wRw2vf5fdDJHcCcuAzANBgkq
# hkiG9w0BAQwFADBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMYQXNzZWNvIERhdGEg
# U3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gVGltZXN0YW1waW5nIDIwMjEg
# Q0EwHhcNMjYwMzExMDczNDU0WhcNMzYwMjI3MDczNDU0WjBQMQswCQYDVQQGEwJQ
# TDEhMB8GA1UECgwYQXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMR4wHAYDVQQDDBVD
# ZXJ0dW0gVGltZXN0YW1wIDIwMjYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC4vc3wcPsSNdoYthfbjUATTkk5EyItd37odw4lsmyOd/dmwXycOrTu8w7O
# 1Kj/63o1X+MRU1N1zTj7LjhZD+UjxbJ1sJ91SS/jYTYbLro72LELWkJ7zaNcJOOq
# 3k4MLNS/DhRHSmsYMqk+MzkMfNZi8DWUqlzVPUa2/aACViReDMnc/gtXm7tA9Pr4
# DN7agEPE1NtN36oCgj6iHR5aGhah/XskfvLZ6ZstoZ5zefWTrZrLh3kcH+YkzoZY
# X9Hf6qqrizkiBj4BlS9R4+VwVKMdjhO7UEa/pf8cTWy+jrsATuAGthG7sWIN+3KV
# 7+Ytv5Uy+DQEgf3bn/VuH4wN0aPhj/mwueJ9jmIjNwqvM/dno8fBeR1jtnuP++Xg
# veQfbTMP3qu9dPRg8ltvtrreQZ9KPDFyUxEZMsrLVm6nJ1JKJgPe6n4gwsL6Vrjj
# HX0zpLF3vUvsQ8TiWgm4sk4r4D7pcXE/rX0E0Vwa+VMLT73PiDZ2nzhIpc1RwNdb
# b/qR3Mpa8sQXNPHFIoX/7bapGUtG5sd1cUGsvLqIWk6dP/xAgPb2BludUinSTCYV
# 7ysiHQS8vFmDXIU7fMkSE7/QHcYPSahro4fk5z9W1t2kIxbZRJe0s4DXiPDlQPwi
# QFllLkU9wLvU6DqR8v35a65J4TeIXhMO/+iCzL+B0rI9GGeKLQIDAQABo4IBUDCC
# AUwwdQYIKwYBBQUHAQEEaTBnMDsGCCsGAQUFBzAChi9odHRwOi8vc3ViY2EucmVw
# b3NpdG9yeS5jZXJ0dW0ucGwvY3RzY2EyMDIxLmNlcjAoBggrBgEFBQcwAYYcaHR0
# cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAfBgNVHSMEGDAWgBS+VAIvv0Bsc0PO
# rAklTp5DRBru4DAMBgNVHRMBAf8EAjAAMDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6
# Ly9zdWJjYS5jcmwuY2VydHVtLnBsL2N0c2NhMjAyMS5jcmwwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMCIGA1UdIAQbMBkwCAYGZ4EMAQQC
# MA0GCyqEaAGG9ncCBQELMB0GA1UdDgQWBBQjOWooq5oSp6Sn8h/5RZq/jf6CAzAN
# BgkqhkiG9w0BAQwFAAOCAgEAZv6Tm6wL3k6mBTwkrYcTVcAR01uE37gUGNihgnTJ
# R+gC41T2H9lwETRjE10nEdCUNv3Ni8S6aBx4UcMRX93fd9w4RUteua2I+oj0kCpu
# Na3PQDKUwozHZmotWivaPO9KTs08y0YVhVSMZvuUH/reFec9eLT6FLAFnX0Sg9Wc
# 7833uQB5RPa8TmXBkTolC8bNxHX+2SfEWSNI8w/Y7o9qBF9l0uwVSrjQitVtIdZo
# 2qb9NvMqqPFLWYef9SG+PGMqfPAQ2EoYeT0hlFLkubWF1X3HbiDwXtz3TU2EWHU+
# VTcZMC4IzMyHK/+kh9n3oxSQ45wsY71y7mqxKyYPyHSPoV3RiAQ1Thr9c65BeJLa
# ELxWSKeQyAGIdBsMlIXPO6qp+VGmE49vosogQ0jYe2hgq5LgJ6oO0Ie364V/kITB
# nifUqS6Zxu+qjfOYS8o72EeoEWIi04/BuH8Y6leNNP27j8NKwaPciWcqv/HBnQji
# zzmH/aqXn03K2SnjvaYPlCR8fFAAW2k6os0cZvLFEhMnHHAghYSIrdwCP98Brkjg
# A3ogOu+jXEO/nbD9OGL873Te6U2TcoOu9lqQQyXYNHiLR5eMqJrzXiDlodarOEKj
# lukyPDnLIuLkg0y6K8S1A5wU8CkM86cXdWFHLRIEYd9kdCfRZBZHhK7iVPeEZYxa
# 9bgwgga5MIIEoaADAgECAhEA5/9pxzs1zkuRJth0fGilhzANBgkqhkiG9w0BAQwF
# ADCBgDELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVz
# IFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEk
# MCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMB4XDTIxMDUxOTA1
# MzIwN1oXDTM2MDUxODA1MzIwN1owVjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFz
# c2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVtIFRpbWVzdGFt
# cGluZyAyMDIxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6RIf
# BDXtuV16xaaVQb6KZX9Od9FtJXXTZo7b+GEof3+3g0ChWiKnO7R4+6MfrvLyLCWZ
# a6GpFHjEt4t0/GiUQvnkLOBRdBqr5DOvlmTvJJs2X8ZmWgWJjC7PBZLYBWAs8sJl
# 3kNXxBMX5XntjqWx1ZOuuXl0R4x+zGGSMzZ45dpvB8vLpQfZkfMC/1tL9KYyjU+h
# tLH68dZJPtzhqLBVG+8ljZ1ZFilOKksS79epCeqFSeAUm2eMTGpOiS3gfLM6yvb8
# Bg6bxg5yglDGC9zbr4sB9ceIGRtCQF1N8dqTgM/dSViiUgJkcv5dLNJeWxGCqJYP
# gzKlYZTgDXfGIeZpEFmjBLwURP5ABsyKoFocMzdjrCiFbTvJn+bD1kq78qZUgAQG
# Gtd6zGJ88H4NPJ5Y2R4IargiWAmv8RyvWnHr/VA+2PrrK9eXe5q7M88YRdSTq9TK
# bqdnITUgZcjjm4ZUjteq8K331a4P0s2in0p3UubMEYa/G5w6jSWPUzchGLwWKYBf
# eSu6dIOC4LkeAPvmdZxSB1lWOb9HzVWZoM8Q/blaP4LWt6JxjkI9yQsYGMdCqwl7
# uMnPUIlcExS1mzXRxUowQref/EPaS7kYVaHHQrp4XB7nTEtQhkP0Z9Puz/n8zIFn
# USnxDof4Yy650PAXSYmK2TcbyDoTNmmt8xAxzcMCAwEAAaOCAVUwggFRMA8GA1Ud
# EwEB/wQFMAMBAf8wHQYDVR0OBBYEFL5UAi+/QGxzQ86sCSVOnkNEGu7gMB8GA1Ud
# IwQYMBaAFLahVDkCw6A/joq8+tT4HKbROg79MA4GA1UdDwEB/wQEAwIBBjATBgNV
# HSUEDDAKBggrBgEFBQcDCDAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vY3JsLmNl
# cnR1bS5wbC9jdG5jYTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAoBggrBgEFBQcwAYYc
# aHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAyBggrBgEFBQcwAoYmaHR0cDov
# L3JlcG9zaXRvcnkuY2VydHVtLnBsL2N0bmNhMi5jZXIwOQYDVR0gBDIwMDAuBgRV
# HSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkq
# hkiG9w0BAQwFAAOCAgEAuJNZd8lMFf2UBwigp3qgLPBBk58BFCS3Q6aJDf3TISoy
# tK0eal/JyCB88aUEd0wMNiEcNVMbK9j5Yht2whaknUE1G32k6uld7wcxHmw67vUB
# Y6pSp8QhdodY4SzRRaZWzyYlviUpyU4dXyhKhHSncYJfa1U75cXxCe3sTp9uTBm3
# f8Bj8LkpjMUSVTtMJ6oEu5JqCYzRfc6nnoRUgwz/GVZFoOBGdrSEtDN7mZgcka/t
# S5MI47fALVvN5lZ2U8k7Dm/hTX8CWOw0uBZloZEW4HB0Xra3qE4qzzq/6M8gyoU/
# DE0k3+i7bYOrOk/7tPJg1sOhytOGUQ30PbG++0FfJioDuOFhj99b151SqFlSaRQY
# z74y/P2XJP+cF19oqozmi0rRTkfyEJIvhIZ+M5XIFZttmVQgTxfpfJwMFFEoQrSr
# klOxpmSygppsUDJEoliC05vBLVQ+gMZyYaKvBJ4YxBMlKH5ZHkRdloRYlUDplk8G
# Ua+OCMVhpDSQurU6K1ua5dmZftnvSSz2H96UrQDzA6DyiI1V3ejVtvn2azVAXg6N
# njmuRZ+wa7Pxy0H3+V4K4rOTHlG3VYA6xfLsTunCz72T6Ot4+tkrDYOeaU1pPX1C
# BfYj6EW2+ELq46GP8KCNUQDirWLU4nOmgCat7vN0SD6RlwUiSsMeCiQDmZwgwrUx
# ggXmMIIF4gIBATAuMBoxGDAWBgNVBAMMD01pY2hhbCBHYWpkYSBDQQIQU1wOlROG
# SZJGSSTWMWQ0eDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD2L6K1wv2HJolc+V13Rpuz
# UtgMu5ABFz3wrmTCLTnIUDANBgkqhkiG9w0BAQEFAASCAQDDFGNlvcfwTkH8KZ3R
# 9zchQiDl0azwIL++MQFomOz+oFym2f8ZSqUDKhgZh4dk6/zcdw7CWOLAHhwESQXy
# T2Nn0QFvX9+KUZ5LLvnilCSnurwLDk+B1pTnOXuNoFhRj5jIFryhJv80nkMRYXD5
# pEJ+5cXr1zgBYtuaQESTV9Sjj6m4kO2HAowW9G5Z1boUXHky/y4MHlRA5CzwFknX
# OEmbaZpJJ/IOC+qh9VA6YY6mY3/H4MKGkDfFMMhJdDwfR4JMyoMbt8KGKlJiG6Qj
# 0YfcLWGk9bbCWAsKoD21C9sfVddcDzLb7w2k64euoV4WCh5pWZg4mkmA3k2ASydm
# CNMWoYIEAjCCA/4GCSqGSIb3DQEJBjGCA+8wggPrAgEBMGowVjELMAkGA1UEBhMC
# UEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMb
# Q2VydHVtIFRpbWVzdGFtcGluZyAyMDIxIENBAhAo8HfBHDa9/l90MkdwJy4DMA0G
# CWCGSAFlAwQCAgUAoIIBVjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MTEwOTEwNTIwN1owNwYLKoZIhvcNAQkQAi8xKDAmMCQw
# IgQghb6Q4QrSQ418ySi2r0iwmrIIF3zs+LASbFjTkQUlxDwwPwYJKoZIhvcNAQkE
# MTIEMEQxZxdTkV4XpLYp9wHWfyyg+HyhUjVtQJwTed5ktyiGvMQIwTopuhKr3h4h
# sDD96jCBnwYLKoZIhvcNAQkQAgwxgY8wgYwwgYkwgYYEFFcUaEEMqFrzQk75FkpR
# NhD0042YMG4wWqRYMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0
# YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBUaW1lc3RhbXBpbmcgMjAy
# MSBDQQIQKPB3wRw2vf5fdDJHcCcuAzANBgkqhkiG9w0BAQEFAASCAgCbrj79X90y
# 4aPtfZN7REURDRC22SjvUCP/6uWUraD6cEpQTaaekiVBetzVJ2Z1AkAY93bZKPxl
# FRmu25oN+5CbHazEQWvnCSOIt+A3tkzZyIIjA6j551mVEyFRrGKAv52vdQlvNr+9
# BjSLwN8TxnENdz0IjRqp35okZvYFw0RThFY5pVyNR4+1QJRZDhJo0pkrcnsVpgeW
# e4eceMx7E1E3YM1iDSeDl4tTIbRLVO6Lc6xUMgNyaSOQPXsPjOEQ4crAjy0i4VQ0
# EkswCMNBcs777KuJhm+QmMuglesuvizUj8+oib21vh8Lc8fffTbci3pq6QxRp+K3
# cnma/s6ROFkJoodjToHsetFC1qwhJpjfgOnj946U1w++Rh7rBZN3RLz5BoR02t60
# 6uLqOqkWAe2DtsJZqgiS6YlLIxbauur3DrBWlKr3RgytewfmOf3KGJEO8VsTPPvO
# Sy5y4y+KVFvQnq1WeWGgCdWYo1A9wYpAjmMYcMbeFvd5jd3GA1HQZAEVcXbvrjOc
# 6LBULC3JZRVQ6Bm1yGKXGdfrt5/hcZYWJGov7W7/mIEKgNHYMEwkUoOI8dV8tlZ3
# HSbwAlpsBXPy0VEut9B0VJ23hVwOIZcarnMk+9pCDBdoaMagIcanmG39Hy0ZHox8
# gZT3ywYzbrrAPQeDLz1Zub3cx1ievBZggA==
# SIG # End signature block
