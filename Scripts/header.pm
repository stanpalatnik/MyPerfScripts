#func(row,col,string,leftboundary,rightboundary)
sub a
{
my ($a,$b,$c) = @_;
my $d = shift || 12;
print "Function values are $a, $b, $c, $d\n";
}

&a(1,2,3,4);
&a(1,2,3);
