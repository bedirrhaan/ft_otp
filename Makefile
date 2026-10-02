NAME = ft_otp

all: $(NAME)

$(NAME): ft_otp.py
	cp ft_otp.py $(NAME)
	chmod +x $(NAME)

clean:
	rm -f ft_otp.key

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
