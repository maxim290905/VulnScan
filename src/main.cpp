#include "xss.h"
#include "menu.h"
#include "sqlinj.h"
#include "csrf.h"
#include "fupload.h"
#include "pch.h"

int main() {
    std::string target_url = input_target_url();
    handle_option(target_url);
    return 0;
}