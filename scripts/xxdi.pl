#!/usr/bin/env perl
#
# xxdi.pl - perl implementation of 'xxd -i' mode
#
# Copyright 2013 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
# Copyright 2013 Linux Foundation
#
# Released under the GPLv2.
#
# Implements the "basic" functionality of 'xxd -i' in perl to keep build
# systems from having to build/install/rely on vim-core, which not all
# distros want to do.  But everyone has perl, so use it instead.
#

use strict;
use warnings;

my $indata;
my $var_name = "stdin";
my $full_output = 1;

{
	local $/;
	my $fh;

	if ($#ARGV == 1 && $ARGV[0] eq '-i') {
		$var_name = $ARGV[1];
		open($fh, '<:raw', $var_name) || die("xxdi.pl: Unable to open $var_name: $!\n");
	} elsif ((!@ARGV && !(-t STDIN)) || ($#ARGV == 0 && $ARGV[0] eq '-i')) {
		$fh = \*STDIN;
		$full_output = 0 if @ARGV;
	} else {
		die "usage: xxdi.pl [-i] [infile]\n";
	}

	$indata = readline $fh;

	close $fh;
}

my $len_data = length($indata);
my $num_digits_per_line = 12;
my $outdata = "";

# Use the variable name of the file we read from, converting '/' and '.
# to '_', or, if this is stdin, just use "stdin" as the name.
$var_name =~ s/\//_/g;
$var_name =~ s/\./_/g;
$var_name = "__$var_name" if $var_name =~ /^\d/;

$outdata = "unsigned char $var_name\[] = { " if ($full_output);

for (my $key= 0; $key < $len_data; $key++) {
	if ($key % $num_digits_per_line == 0) {
		$outdata = substr($outdata, 0, -1)."\n  ";
	}
	$outdata .= sprintf("0x%.2x, ", ord(substr($indata, $key, 1)));
}

$outdata = substr($outdata, 0, -2);

if ($full_output) {
	$outdata .= "\n};\nunsigned int $var_name\_len = $len_data;\n";
} else {
	$outdata .= "\n";
}

binmode STDOUT;
print {*STDOUT} $outdata;

