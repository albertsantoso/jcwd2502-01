import React from "react";

import Footer from "../../components/layouts/shared/Footer";
import ProductMediaImage from "../../components/layouts/user/ProductMediaImage";
import ProductDetailContent from "../../components/sections/public/ProductDetailContent";
import OrderAction from "../../components/layouts/user/OrderAction";

const ProductPage = () => {
	return (
		<>
			<main className="product-page pb-48 md:max-w-[1232px] md:mx-auto md:py-12 md:pb-20 md:min-h-[88vh]">
				<section className="md:grid md:grid-cols-3 relative">
					<ProductMediaImage />
					<ProductDetailContent />
					<OrderAction />
				</section>
			</main>
			<footer className="hidden md:block">
				<Footer />
			</footer>
		</>
	);
};

export default ProductPage;
