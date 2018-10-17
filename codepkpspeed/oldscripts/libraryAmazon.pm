package libraryAmazon;
use strict;
use warnings;
use Excel::Writer::XLSX;

BEGIN
{
    use Exporter;
    our @ISA   = qw(Exporter);
    our @EXPORT= qw( &insertTPS &insertCpu &printheader $file1 $file2 $result1 $result2 $outputFile
                     $file3 $file4 $workbook &header_ws1 &header_ws2 &header_ws3 &header_ws4 %sheetname );
};

our ($file1, $file2, $file3, $file4, $result1, $result2, $outputFile);
our $firmware = "FW2.05-13";

$file1="result_blocking";
$file2="result_nonblocking";
$file3="blockingCpu";
$file4="nonblockingCpu";
$outputFile="performance_benchmarking_amazon_2.05_release.xlsx";
our %sheetname =
(
    B2TPS     => "B2Cores$firmware",
    NB2TPS    => "NB2Cores$firmware",
    B63TPS    => "B63Cores$firmware",
    NB63TPS   => "NB63Cores$firmware",
    B2CPU     => "B2CoresCPU$firmware",
    NB2CPU    => "NB2CoresCPU$firmware",
    B63CPU    => "B63CoresCPU$firmware",
    NB63CPU   => "NB63CoresCPU$firmware",
);

our $workbook = Excel::Writer::XLSX->new($outputFile);
my $headerformat = $workbook->add_format(
    border => 1,
    valign => 'vcenter',
    align  => 'center',
    bold   => 1,
);
my $format = $workbook->add_format(
    border => 1,
    valign => 'vcenter',
    align  => 'center',
);

sub insertTPS
{
    my ($worksheet, $row, $col, $string, $lfbndry, $rgbndry, $count, $incrow, $inccol) = @_;
    $row+=$incrow if ($count==$lfbndry);
    $col=$inccol if ($count==$lfbndry);
    if ($count>$lfbndry && $count <=$rgbndry){
        $worksheet->write($row, $col, $string, $format);
        $col++;
    }
    return ($row, $col);
}

sub insertCpu
{
    my $worksheet = shift;
    my $reflines  = shift;
    my $row = shift;
    my $col = shift;
    my @lines=@$reflines;
    foreach my $line (@lines){
        chomp $line;
        my @split=split(' ', $line);
        foreach my $aa (@split){
            chomp $aa;
            $worksheet->write( $row, $col, $aa, $format);
            $col++;
        }
        $col=2;
        $row++;
    }
    return ($row,$col);
}

sub header_ws1
{
    my ($ws, $col) = @_;
    my $constcol=$col;
    ## WorkSheet1 (Blocking Values)
    $ws->write( 'B4', 'No of Threads', $headerformat );
    $ws->write( 'C4', 'Modulus Bits', $headerformat );
    $ws->write( 'C5', '2048', $headerformat );
    $ws->write( 'C6', '3072', $headerformat );
    $ws->merge_range( 'B5:B6', '100', $headerformat );
    &printheader($ws, 3,$col,"RSA_NONCRT with StaticKey"); $col++;
    &printheader($ws, 3,$col++,"RSA_NONCRT without StaticKey");
    &printheader($ws, 3,$col++,"RSA_CRT with StaticKey");
    &printheader($ws, 3,$col++,"RSA_CRT without StaticKey");
    &printheader($ws, 3,$col++,"RSAServerFull"); $col=$constcol;
    &printheader($ws, 8,$col++,"DES Record Enc");
    &printheader($ws, 8,$col++,"AES128 Record Enc");
    &printheader($ws, 8,$col++,"AES256 Record Enc");
    &printheader($ws, 8,$col++,"AESGCM128 Record Enc");
    &printheader($ws, 8,$col++,"AESGCM256 Record Enc");
    &printheader($ws, 8,$col++,"3DES-CBC");
    &printheader($ws, 8,$col++,"Basic AES128");
    &printheader($ws, 8,$col++,"Basic AES192");
    &printheader($ws, 8,$col++,"Basic AES256"); $col=$constcol;
    &printheader($ws, 22,2,"Fips Random"); $col=$constcol;
    &printheader($ws, 25,$col,"ECDHFull");

    $ws->write( 'B9', 'No of Threads', $headerformat );
    $ws->merge_range( 'B10:B21', '100', $headerformat );
    $ws->write( 'C9', 'Data Length (Bytes)', $headerformat ); my $j=10;
    for (my $i=16;$i<=16384;$i=$i*2){
        $ws->write( "C$j", $i, $headerformat );
        $j++ if ($i==2048);
        $ws->write( "C$j", 3072, $headerformat ) if ($i==2048);
        $j++;
    }

    $ws->write( 'B23', 'No of Threads', $headerformat );
    $ws->write( 'B24', '100', $headerformat );

    $ws->write( 'B26', 'No of Threads', $headerformat );
    $ws->merge_range( 'B27:B28', '100', $headerformat );
    $ws->write( 'B24', '100', $headerformat );
    $ws->write( 'C26', 'Curve IDs', $headerformat );
    $ws->write( 'C27', 'P256', $headerformat );
    $ws->write( 'C28', 'P384', $headerformat );
}

sub header_ws2
{
    my ($ws, $col) = @_;
    my $constcol=$col;
    ## WorkSheet1 (Blocking Values)
    $ws->write( 'B4', 'No of Threads', $headerformat );
    $ws->write( 'C4', 'Modulus Bits', $headerformat );
    $ws->write( 'C5', '2048', $headerformat );
    $ws->write( 'C6', '3072', $headerformat );
    $ws->merge_range( 'B5:B6', '100', $headerformat );
    &printheader($ws, 3,$col,"RSA_NONCRT with StaticKey"); $col++;
    &printheader($ws, 3,$col++,"RSA_NONCRT without StaticKey");
    &printheader($ws, 3,$col++,"RSA_CRT with StaticKey");
    &printheader($ws, 3,$col++,"RSA_CRT without StaticKey");$col=$constcol;
    &printheader($ws, 8,$col++,"3DES-CBC");
    &printheader($ws, 8,$col++,"Basic AES128");
    &printheader($ws, 8,$col++,"Basic AES256");

    $ws->write( 'B9', 'No of Threads', $headerformat );
    $ws->merge_range( 'B10:B21', '100', $headerformat );
    $ws->write( 'C9', 'Data Length (Bytes)', $headerformat ); my $j=10;
    for (my $i=16;$i<=16384;$i=$i*2){
        $ws->write( "C$j", $i, $headerformat );
        $j++ if ($i==2048);
        $ws->write( "C$j", 3072, $headerformat ) if ($i==2048);
        $j++;
    }
}

sub header_ws3
{
    my ($ws, $col) = @_;
    my $constcol=$col;
    ## WorkSheet3 (pkpSpeed Blocking CPU Values)
    $ws->write( 'A2', 'Server CPU (Idle Time)', $headerformat );
    $ws->write( 'A3', 'RSA 2048 non crt with static', $headerformat );
    $ws->write( 'A4', 'RSA 2048 non crt without static', $headerformat );
    $ws->write( 'A5', 'RSA 2048 crt with static', $headerformat );
    $ws->write( 'A6', 'RSA 2048 crt without static', $headerformat );
    $ws->write( 'A7', 'RSA 3072 non crt with static', $headerformat );
    $ws->write( 'A8', 'RSA 3072 non crt without static', $headerformat );
    $ws->write( 'A9', 'RSA 3072 crt with static', $headerformat );
    $ws->write( 'A10', 'RSA 3072 crt without static', $headerformat );
    $ws->write( 'A11', 'RSA 2048 RSAServerFull', $headerformat );
    $ws->write( 'A12', 'RSA 3072 RSAServerFull', $headerformat );
    $ws->write( 'A13', 'ECDHFull P256', $headerformat );
    $ws->write( 'A14', 'ECDHFull P384', $headerformat );
    $ws->write( 'A15', 'Fips Random', $headerformat );
    $ws->write( 'A16', 'DES Record Encrypt', $headerformat );        &printbytes($ws, "A", 17);
    $ws->write( 'A29', 'AES 128 Record Encrypt', $headerformat );    &printbytes($ws, "A", 30);
    $ws->write( 'A42', 'AES 256 Record Encrypt', $headerformat );    &printbytes($ws, "A", 43);
    $ws->write( 'A55', 'AESGCM 128 Record Encrypt', $headerformat ); &printbytes($ws, "A", 56);
    $ws->write( 'A68', 'AESGCM 256 Record Encrypt', $headerformat ); &printbytes($ws, "A", 69);
    $ws->write( 'A81', '3DES-CBC', $headerformat );                  &printbytes($ws, "A", 82);
    $ws->write( 'A94', 'AES 128', $headerformat );                   &printbytes($ws, "A", 95);
    $ws->write( 'A107', 'AES 192', $headerformat );                  &printbytes($ws, "A", 108);
    $ws->write( 'A120', 'AES 256', $headerformat );                  &printbytes($ws, "A", 121);
}

sub header_ws4
{
    my ($ws, $col) = @_;
    my $constcol=$col;
    ## WorkSheet3 (pkpSpeed Blocking CPU Values)
    $ws->write( 'A2', 'Server CPU (Idle Time)', $headerformat );
    $ws->write( 'A3', 'RSA 2048 non crt with static', $headerformat );
    $ws->write( 'A4', 'RSA 2048 non crt without static', $headerformat );
    $ws->write( 'A5', 'RSA 2048 crt with static', $headerformat );
    $ws->write( 'A6', 'RSA 2048 crt without static', $headerformat );
    $ws->write( 'A7', 'RSA 3072 non crt with static', $headerformat );
    $ws->write( 'A8', 'RSA 3072 non crt without static', $headerformat );
    $ws->write( 'A9', 'RSA 3072 crt with static', $headerformat );
    $ws->write( 'A10', 'RSA 3072 crt without static', $headerformat );
    $ws->write( 'A11', '3DES-CBC', $headerformat );  &printbytes($ws, "A", 12);
    $ws->write( 'A24', 'AES 128', $headerformat );   &printbytes($ws, "A", 25);
    $ws->write( 'A37', 'AES 256', $headerformat );   &printbytes($ws, "A", 38);
}

sub printbytes
{
    my $ws     = shift;
    my $rowidx = shift;
    my $j      = shift;
    for (my $i=16;$i<=16384;$i=$i*2){
        my $cellval = $rowidx.$j;
        $ws->write( "$cellval", $i, $headerformat );
        if ($i==2048) {
            $j++ if ($i==2048);
            my $cellval = $rowidx.$j;
            $ws->write( "$cellval", 3072, $headerformat );
        }
        $j++;
    }
}

sub printheader
{
    my ($worksheet, $row, $col, $string) = @_;
    $worksheet->write($row, $col, $string, $headerformat);
}

1;
