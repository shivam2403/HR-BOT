# pull official base image
FROM node:18-alpine

# set working directory
WORKDIR /usr/src/frontend

# add `/usr/src/frontend/node_modules/.bin` to $PATH
ENV PATH /usr/src/frontend/node_modules/.bin:$PATH

# install and cache app dependencies
COPY package.json .
COPY package-lock.json .

# install dependencies
RUN npm install

# Copy the entire frontend directory into the working directory
COPY . .

# start app
CMD ["npm", "start"]
