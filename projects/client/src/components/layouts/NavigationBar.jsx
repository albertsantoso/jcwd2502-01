import { useEffect, useState } from "react";

import { useFormik } from "formik";

import { IoSearch, IoCartOutline } from "react-icons/io5";

import { Link, useLocation, useNavigate } from "react-router-dom";
import NexocompLogo from "../../assets/logo/NexocompLogo";

import {
	Navbar,
	NavbarBrand,
	NavbarContent,
	NavbarItem,
	Button,
	NavbarMenu,
	NavbarMenuToggle,
	Input,
	NavbarMenuItem,
} from "@nextui-org/react";

import NexoLogo from "../../assets/logo/NexoLogo";
import { useDispatch, useSelector } from "react-redux";
import { onSearch, setSearch } from "../../redux/features/products";

const NavigationBar = () => {
	const [isMenuOpen, setIsMenuOpen] = useState(false);

	const dispatch = useDispatch();
	const navigate = useNavigate();
	const location = useLocation();

	const search = useSelector((state) => state.products.search);

	// const takeFromQuery = () => {
	// 	const queryParams = new URLSearchParams(location.search);
	// 	const selectedSearch = queryParams.get("search");
	// 	if (selectedSearch) {
	// 		dispatch(setSearch(selectedSearch));
	// 	}
	// };

	const formik = useFormik({
		initialValues: { searchQuery: "" },
		onSubmit: (values) => {
			// Handle the search query submission here
			dispatch(onSearch(values.searchQuery));
			navigate("/explore");
		},
	});

	// useEffect(() => {
	// 	takeFromQuery();
	// }, []);

	useEffect(() => {
		formik.setFieldValue("searchQuery", search);
	}, [search]);

	return (
		<>
			<Navbar
				onMenuOpenChange={setIsMenuOpen}
				maxWidth="full"
				className="md:py-2 shadow-sm bg-background border-b-2 dark:border-neutral-800"
				isBlurred={false}
			>
				<NavbarContent className="hidden md:flex">
					<NavbarBrand>
						<Link to={"/"}>
							<div className="-mb-1.5 w-full">
								<NexocompLogo
									width={160}
									fill={"fill-primary-500"}
								/>
							</div>
						</Link>
					</NavbarBrand>
				</NavbarContent>
				<NavbarContent className="md:hidden flex">
					<NavbarBrand>
						<Link to={"/"}>
							<div className=" w-full">
								<NexoLogo
									width={64}
									fill={"fill-primary-500"}
								/>
							</div>
						</Link>
					</NavbarBrand>
				</NavbarContent>
				<NavbarContent className="flex gap-4 w-full" justify="center">
					<form className="w-full" onSubmit={formik.handleSubmit}>
						<Input
							type="text"
							placeholder="Search on Nexocomp"
							startContent={<IoSearch opacity={".5"} />}
							variant="bordered"
							fullWidth
							onChange={(e) =>
								formik.setFieldValue(
									"searchQuery",
									e.target.value
								)
							}
							value={formik.values.searchQuery}
						/>
					</form>
				</NavbarContent>
				<NavbarContent justify="end" className="hidden md:flex">
					<Link to={"/cart"}>
						<Button isIconOnly aria-label="Cart" variant="flat">
							<IoCartOutline size={22} className="fill-accent" />
						</Button>
					</Link>
				</NavbarContent>
				<NavbarContent justify="end" className="gap-2 hidden md:flex">
					<NavbarItem className="">
						<Link to={"/login"}>
							<Button className="bg-secondary-500 text-white font-medium hover">
								Login
							</Button>
						</Link>
					</NavbarItem>
					<NavbarItem className="">
						<Link to={"/signup"}>
							<Button className="bg-primary-500 text-black font-medium hover">
								Sign Up
							</Button>
						</Link>
					</NavbarItem>
				</NavbarContent>
				<NavbarContent className="sm:hidden">
					<NavbarMenuToggle
						aria-label={isMenuOpen ? "Close menu" : "Open menu"}
					/>
				</NavbarContent>
				<NavbarMenu className="pt-4">
					<NavbarMenuItem>
						<div className="flex justify-between gap-2">
							<Link to={"/login"} className="w-full">
								<Button
									className="bg-secondary-500 text-white font-medium hover"
									fullWidth
								>
									Login
								</Button>
							</Link>
							<Link to={"/signup"} className="w-full">
								<Button
									className="bg-primary-500 text-black font-medium hover"
									fullWidth
								>
									Sign Up
								</Button>
							</Link>
						</div>
					</NavbarMenuItem>
				</NavbarMenu>
			</Navbar>
		</>
	);
};

export default NavigationBar;
