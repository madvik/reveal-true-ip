<?php
/**
* @author Pierre lannoy (https://github.com/Pierre-Lannoy)
* 
*/

function ply_expand( $ip ) {
	if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
		return ply_expand_v6( $ip );
	}
	if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
		return ply_expand_v4( $ip );
	}
	return '';
}

function ply_expand_v4( $ip ) {
	return long2ip( ip2long( str_replace( [ '"', '%' ], '', $ip ) ) );
}

function ply_expand_v6( $ip ) {
	return implode( ':', str_split( bin2hex( inet_pton( str_replace( [ '"', '%' ], '', $ip ) ) ), 4 ) );
}

function ply_maybe_extract_ip( $iplist, $include_private = false ) {
	if ( $include_private ) {
		foreach ( $iplist as $ip ) {
			if ( filter_var( trim( $ip ), FILTER_VALIDATE_IP ) ) {
				return ply_expand( $ip );
			}
		}
	}
	foreach ( $iplist as $ip ) {
		if ( filter_var( trim( $ip ), FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return ply_expand( $ip );
		}
	}
	return '';
}

function ply_get_current() {
	for ( $i = 0 ; $i < 2 ; $i++ ) {
		foreach (
			[
				'REMOTE_ADDR',
				'HTTP_X_REAL_IP',
				'HTTP_CF_CONNECTING_IP',
				'HTTP_X_CLUSTER_CLIENT_IP',
				'TRUE-CLIENT-IP',
			] as $field
		) {
			if ( array_key_exists( $field, $_SERVER ) ) {
				$ip = ply_maybe_extract_ip( explode( ',', filter_input( INPUT_SERVER, $field ) ), 1 === $i );
				if ( '' !== $ip ) {
					return $ip;
				}
			}
		}
		foreach (
			[
				'HTTP_X_FORWARDED_FOR',
				'HTTP_CLIENT_IP',
				'HTTP_X_FORWARDED',
				'HTTP_FORWARDED_FOR',
				'HTTP_FORWARDED',
			] as $field
		) {
			if ( array_key_exists( $field, $_SERVER ) ) {
				$ip = ply_maybe_extract_ip( array_reverse( explode( ',', filter_input( INPUT_SERVER, $field ) ) ), 1 === $i );
				if ( '' !== $ip ) {
					return $ip;
				}
			}
		}
	}
	return '127.0.0.1';
}

$_SERVER['REMOTE_ADDR'] = ply_get_current();
?>
