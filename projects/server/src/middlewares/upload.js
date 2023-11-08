const { multerUpload } = require("./../lib/multer");
const { deleteFiles } = require("./../helper/deleteFiles");

const upload = async (req, res, next) => {
	const result = multerUpload.fields([{ name: "images", maxCount: 3 }]);
	result(req, res, function (err) {
		try {
			if (err) throw err;

			if (!req.files.images) return next();

			req.files?.images?.forEach((v) => {
				if (v.size > 1000000) {
					throw {
						message: `${v.originalname} is too large`,
						files: req.files,
					};
				}
			});
			console.log("mulupload>>>>", req.files);
			next();
		} catch (error) {
			deleteFiles(error.files);
			next(error);
		}
	});
};

module.exports = upload;
