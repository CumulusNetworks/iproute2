int lwt_parse_encap(struct nlmsghdr *n, int *argcp, char ***argvp);
int lwt_parse_nh_encap(struct rtattr *rta, int *argcp, char ***argvp);
void lwt_print_encap(FILE *fp, struct rtattr *encap_type,
		     struct rtattr *encap);
